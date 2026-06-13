package handler

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vibeswaf/waf/internal/bot"
	"github.com/vibeswaf/waf/internal/domain/app"
	"github.com/vibeswaf/waf/internal/logger"
	"github.com/vibeswaf/waf/internal/metrics"
	"github.com/vibeswaf/waf/internal/pages"
	"github.com/vibeswaf/waf/internal/pipeline"
	handlers "github.com/vibeswaf/waf/internal/pipeline/handlers"
	"github.com/vibeswaf/waf/internal/ratelimit"
	"github.com/vibeswaf/waf/internal/service"
	"github.com/vibeswaf/waf/internal/transport"
)


type WAFHandler struct {
	wafService     *service.WAFService
	appService     *service.AppService
	logger         *logger.Clickhouse
	pipeline       *pipeline.Pipeline
	maxmind        *service.MaxMindService
	appConfig      AppConfig
	flood          *ratelimit.FloodProtector
	trustedHistory *handlers.TrustedHistoryScorer
}


type AppConfig interface {
	IsDebug() bool
	LogDebug(format string, v ...interface{})
	LogInfo(format string, v ...interface{})
	LogWarn(format string, v ...interface{})
	LogError(format string, v ...interface{})
}


func NewWAFHandler(wafService *service.WAFService, appService *service.AppService, logger *logger.Clickhouse, p *pipeline.Pipeline, maxmind *service.MaxMindService, appConfig AppConfig, flood *ratelimit.FloodProtector, trustedHistory *handlers.TrustedHistoryScorer) *WAFHandler {
	return &WAFHandler{
		wafService:     wafService,
		appService:     appService,
		logger:         logger,
		pipeline:       p,
		maxmind:        maxmind,
		appConfig:      appConfig,
		flood:          flood,
		trustedHistory: trustedHistory,
	}
}

func (h *WAFHandler) AppService() *service.AppService {
	return h.appService
}


func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Resolve app first so TrustedProxies can be used for IP extraction.
	var resolvedApp *app.App
	appID := "default"
	var trustedProxies []string
	if h.appService != nil {
		if a, err := h.appService.GetAppByDomain(r.Host); err == nil && a != nil {
			resolvedApp = a
			appID = a.ID
			trustedProxies = a.Config.Advanced.TrustedProxies
			h.appConfig.LogDebug("[WAF] Matched domain %s to app %s", r.Host, appID)
		} else {
			h.appConfig.LogDebug("[WAF] No app found for domain %s, using default", r.Host)
		}
	}

	clientIP := getClientIP(r, trustedProxies)

	ctx := &pipeline.Context{
		Request:  r,
		Writer:   w,
		ClientIP: clientIP,
		AppID:    appID,
	}

	ctx.Key = ratelimit.BuildKey(ctx.ClientIP, r.UserAgent())
// Redirect HTTP → HTTPS before any other processing.
	if resolvedApp != nil && resolvedApp.Config.RedirectHTTPS && r.TLS == nil {
		target := "https://" + r.Host + r.RequestURI
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	// Enforce request body size limit.
	if resolvedApp != nil && resolvedApp.Config.Advanced.RequestSizeLimit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, resolvedApp.Config.Advanced.RequestSizeLimit*1024*1024)
	}

	// Handle CORS preflight before pipeline.
	if resolvedApp != nil && resolvedApp.Config.Advanced.CORS.Enabled && r.Method == http.MethodOptions {
		cors := resolvedApp.Config.Advanced.CORS
		origin := r.Header.Get("Origin")
		for _, o := range cors.AllowOrigins {
			if o == "*" || o == origin {
				if o == "*" {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
				break
			}
		}
		if len(cors.AllowMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
		}
		if len(cors.AllowHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ", "))
		}
		if cors.AllowCreds {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if cors.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cors.MaxAge))
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.maxmind != nil {
		if geoResult, err := h.maxmind.Lookup(ctx.ClientIP); err == nil {
			ctx.Country = geoResult.CountryCode
			ctx.ASN = geoResult.ASN
			ctx.ASNOrg = geoResult.ASNOrg
			ctx.IsDatacenter = geoResult.IsDatacenter
		}
	}

	ctx.HTTPFingerprint = bot.GenerateFingerprint(r)

	if isStaticAsset(r.URL.Path) {
		h.appConfig.LogDebug("[WAF] Skipping WAF for static asset: %s", r.URL.Path)
		if resolvedApp != nil {
			if upstream := resolvedApp.PickUpstream(ctx.ClientIP); upstream != nil {
				h.proxyToUpstream(w, r, resolvedApp, *upstream, ctx.ClientIP)
				return
			}
		}
		pages.ServeDefaultPage(w, r.Host)
		return
	}

	// WebSocket upgrade — partial security pipeline then tunnel.
	// Flow: IP Access → Flood Protection → Upgrade Validation → Tunnel
	// Skips: WAF body scan, bot detection scoring, decision engine.
	if isWebSocketUpgrade(r) {
		if resolvedApp == nil || !resolvedApp.Config.Advanced.AllowWebSocket {
			h.appConfig.LogDebug("[WS] WebSocket denied (not enabled) for %s: %s", r.Host, r.URL.Path)
			http.Error(w, "WebSocket not allowed", http.StatusForbidden)
			return
		}

		// Run Phase 1 partial: IP Access + Flood
		h.pipeline.ExecuteWebSocketChecks(ctx)

		if ctx.Action == "block" {
			h.appConfig.LogDebug("[WS] WebSocket blocked by security check: %s %s", ctx.ClientIP, ctx.Reason)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if ctx.Action == "challenge" {
			h.appConfig.LogDebug("[WS] WebSocket challenged (cannot serve challenge over WS): %s", ctx.ClientIP)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Validate WebSocket upgrade headers
		if !isValidWebSocketUpgrade(r) {
			h.appConfig.LogDebug("[WS] Invalid WebSocket upgrade headers from %s", ctx.ClientIP)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Tunnel
		h.appConfig.LogDebug("[WS] WebSocket tunnel for app %s: %s", appID, r.URL.Path)
		if upstream := resolvedApp.PickUpstream(ctx.ClientIP); upstream != nil {
			if h.logger != nil {
				h.logger.Log(logger.LogEntry{
					TS:     startTime,
					IP:     ctx.ClientIP,
					Host:   r.Host,
					Path:   r.URL.Path,
					UA:     r.UserAgent(),
					Action: "allow",
					Reason: "websocket_upgrade",
					Status: 101,
					AppID:  appID,
				})
			}
			h.proxyWebSocket(w, r, resolvedApp, *upstream, ctx.ClientIP)
			return
		}
		pages.ServeDefaultPage(w, r.Host)
		return
	}

	if resolvedApp != nil && resolvedApp.UnderAttackMode {
		h.appConfig.LogDebug("[WAF] Under Attack mode active for %s, forcing challenge", r.Host)
		ctx.AddDecision(pipeline.Decision{
			Action: "challenge",
			Source: "under_attack_mode",
			Reason: "under_attack_mode",
		})
	}

	pipelineErr := h.pipeline.Execute(ctx)

	if ctx.Action == "" {
		ctx.Action = "allow"
	}

	// Record attack if WAF detected violations (for flood behavioral tracking)
	if h.flood != nil {
		if ctx.WAFStatus > 0 {
			h.flood.RecordAttack(ctx.ClientIP)
		}
	}

	// Any action that is not block/challenge means proxy to upstream
	shouldProxy := ctx.Action != "block" && ctx.Action != "challenge"

	// Trusted history: record clean request or reset on block/challenge
	if h.trustedHistory != nil {
		if shouldProxy {
			h.trustedHistory.RecordCleanRequest(ctx.ClientIP)
		} else {
			h.trustedHistory.ResetHistory(ctx.ClientIP)
		}
	}

	status := http.StatusOK
	if ctx.Action == "block" {
		status = http.StatusForbidden
	} else if ctx.Action == "challenge" {
		status = http.StatusForbidden
	}

	pipelineDuration := time.Duration(ctx.PipelineDurationUS) * time.Microsecond
	var upstreamDuration time.Duration

	if pipelineErr == pipeline.ErrResponseWritten {
		// Response already written by pipeline (e.g. challenge page)
		totalDuration := time.Since(startTime)
		h.logRequest(startTime, r, ctx, appID, status, pipelineDuration, 0, totalDuration)
		return
	}

	if shouldProxy {
		if resolvedApp != nil {
			if upstream := resolvedApp.PickUpstream(ctx.ClientIP); upstream != nil {
				h.appConfig.LogDebug("[PROXY] Forwarding %s %s to %s://%s:%d", r.Method, r.URL.Path, upstream.Scheme, upstream.Host, upstream.Port)
				proxyStart := time.Now()
				h.proxyToUpstream(w, r, resolvedApp, *upstream, ctx.ClientIP)
				upstreamDuration = time.Since(proxyStart)
				status = http.StatusOK
			} else {
				pages.ServeDefaultPage(w, r.Host)
			}
		} else {
			pages.ServeDefaultPage(w, r.Host)
		}
	}

	totalDuration := time.Since(startTime)
	h.logRequest(startTime, r, ctx, appID, status, pipelineDuration, upstreamDuration, totalDuration)
}

func (h *WAFHandler) logRequest(startTime time.Time, r *http.Request, ctx *pipeline.Context, appID string, status int, pipelineDuration, upstreamDuration, totalDuration time.Duration) {
	if h.logger == nil {
		return
	}

	deviceType, osName := logger.ParseUserAgent(r.UserAgent())

	var allReasons []string
	if v, ok := ctx.GetExtra("matched_rules"); ok {
		if matchedRules, ok := v.([]map[string]interface{}); ok {
			allReasons = append(allReasons, handlers.BuildRuleReasons(matchedRules)...)
		}
	}
	if ctx.Reason != "" {
		isDuplicate := false
		for _, rr := range allReasons {
			if rr == ctx.Reason {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			allReasons = append(allReasons, ctx.Reason)
		}
	}
	finalReason := ctx.Reason
	if len(allReasons) > 0 {
		finalReason = strings.Join(allReasons, "|")
	}

	h.logger.Log(logger.LogEntry{
		TS:              startTime,
		IP:              ctx.ClientIP,
		Host:            r.Host,
		Path:            r.URL.Path,
		UA:              r.UserAgent(),
		Action:          ctx.Action,
		Reason:          finalReason,
		Status:          status,
		Latency:         int(totalDuration.Milliseconds()),
		PipelineLatency: int(pipelineDuration.Milliseconds()),
		UpstreamLatency: int(upstreamDuration.Milliseconds()),
		AppID:           appID,
		Country:         ctx.Country,
		ASN:             uint32(ctx.ASN),
		ASNOrg:          ctx.ASNOrg,
		DeviceType:      deviceType,
		OS:              osName,
		CacheHit:        ctx.CacheHit,
		PipelineTrace:   ctx.SerializeTrace(),
	})

	// Record metrics with full precision (nanoseconds)
	metrics.Record(totalDuration, pipelineDuration)
}

func (h *WAFHandler) proxyToUpstream(w http.ResponseWriter, r *http.Request, application *app.App, upstream app.Upstream, clientIP string) {

	// WebSocket upgrade — only if per-app AllowWebSocket is enabled
	if isWebSocketUpgrade(r) && application != nil && application.Config.Advanced.AllowWebSocket {
		h.proxyWebSocket(w, r, application, upstream, clientIP)
		return
	}

	targetURL := upstream.Scheme + "://" + upstream.Host
	if upstream.Port != 80 && upstream.Port != 443 {
		targetURL += fmt.Sprintf(":%d", upstream.Port)
	}

	// Use RawPath to preserve original encoding, fallback to Path
	path := r.URL.RawPath
	if path == "" {
		path = r.URL.Path
	}
	targetURL += path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		h.appConfig.LogWarn("[PROXY] Invalid request URL: %s err=%v", targetURL, err)
		pages.ServeBlockedPage(w, clientIP, r.Host, "Invalid request URL")
		return
	}


	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}
	

	if application != nil {
		advanced := application.Config.Advanced
		

		if advanced.ModifyHostHeader && advanced.HostHeaderValue != "" {

			hostValue := advanced.HostHeaderValue
			if hostValue == "$http_host" {
				hostValue = r.Host
			}
			proxyReq.Host = hostValue
			proxyReq.Header.Set("Host", hostValue)
		} else {

			proxyReq.Host = r.Host
			proxyReq.Header.Set("Host", r.Host)
		}
		

		proxyReq.Header.Set("X-Forwarded-For", clientIP)
		

		proxyReq.Header.Set("X-Real-IP", clientIP)
		

		if advanced.PassXForwardedHost {
			proxyReq.Header.Set("X-Forwarded-Host", r.Host)
		}
		

		if advanced.PassXForwardedProto {
			proto := "http"
			if r.TLS != nil {
				proto = "https"
			}
			proxyReq.Header.Set("X-Forwarded-Proto", proto)
		}
	}


	insecure := application != nil && application.Config.Advanced.AllowInsecureSSL && upstream.Scheme == "https"
	upstreamKey := fmt.Sprintf("%s://%s:%d", upstream.Scheme, upstream.Host, upstream.Port)

	var connectTimeout, readTimeout, sendTimeout int
	if application != nil {
		connectTimeout = application.Config.Advanced.ConnectTimeout
		readTimeout = application.Config.Advanced.ReadTimeout
		sendTimeout = application.Config.Advanced.SendTimeout
	}
	client := transport.GetClient(upstreamKey, insecure, connectTimeout, readTimeout, sendTimeout)


	resp, err := client.Do(proxyReq)
	if err != nil {
		h.appConfig.LogWarn("[PROXY] Upstream unreachable %s: %v", targetURL, err)
		pages.ServeDefaultPage(w, r.Host)
		return
	}
	defer resp.Body.Close()

	// Record error for flood behavioral tracking (4xx/5xx from upstream)
	if h.flood != nil && resp.StatusCode >= 400 {
		h.flood.RecordError(clientIP)
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	if application != nil {
		for _, h := range application.Config.Advanced.AddHeaders {
			if h.Name != "" {
				w.Header().Set(h.Name, h.Value)
			}
		}

		if !application.Config.Advanced.ProxyBuffering {
			w.Header().Set("X-Accel-Buffering", "no")
		}

		// CORS headers.
		cors := application.Config.Advanced.CORS
		if cors.Enabled {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range cors.AllowOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(cors.AllowOrigins) == 1 && cors.AllowOrigins[0] == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
			if len(cors.AllowMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
			}
			if len(cors.AllowHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ", "))
			}
			if len(cors.ExposeHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(cors.ExposeHeaders, ", "))
			}
			if cors.AllowCreds {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			if cors.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cors.MaxAge))
			}
		}

		// Cache-Control headers for static assets.
		cache := application.Config.Advanced.Cache
		if cache.Enabled && isStaticAsset(r.URL.Path) {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", cache.TTL))
		} else if cache.Enabled {
			w.Header().Set("Cache-Control", "no-store")
		}
	}

	w.WriteHeader(resp.StatusCode)
	buf := transport.GetBuffer()
	io.CopyBuffer(w, resp.Body, *buf)
	transport.PutBuffer(buf)
}

func getClientIP(r *http.Request, trustedProxies []string) string {
	if len(trustedProxies) == 0 {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return strings.TrimSpace(cfIP)
		}
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			ips := strings.Split(xff, ",")
			return strings.TrimSpace(ips[0])
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}
	return app.ExtractClientIPStatic(r, trustedProxies)
}

func isStaticAsset(path string) bool {

	pathLower := strings.ToLower(path)
	if strings.HasPrefix(pathLower, "/__waf_verify") {
		return false
	}
	if strings.HasPrefix(pathLower, "/api/") {
		return false
	}
	if strings.HasPrefix(pathLower, "/health") {
		return false
	}
	if strings.HasPrefix(pathLower, "/socket.io/") {
		return true
	}
	

	staticExtensions := []string{
		".js", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".webm", ".ogg",
		".pdf", ".zip", ".tar", ".gz",
	}
	
	for _, ext := range staticExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}
	return false
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func isValidWebSocketUpgrade(r *http.Request) bool {
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Key") == "" {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Version") == "" {
		return false
	}
	return true
}

func (h *WAFHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, application *app.App, upstream app.Upstream, clientIP string) {
	// Build upstream address
	host := upstream.Host
	port := upstream.Port
	addr := fmt.Sprintf("%s:%d", host, port)

	// Dial upstream
	var upstreamConn net.Conn
	var err error

	connectTimeout := 5 * time.Second
	if application != nil && application.Config.Advanced.ConnectTimeout > 0 {
		connectTimeout = time.Duration(application.Config.Advanced.ConnectTimeout) * time.Second
	}

	if upstream.Scheme == "https" {
		dialer := &net.Dialer{Timeout: connectTimeout}
		tlsConfig := &tls.Config{
			ServerName: host,
		}
		if application != nil && application.Config.Advanced.AllowInsecureSSL {
			tlsConfig.InsecureSkipVerify = true //nolint:gosec
		}
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		upstreamConn, err = net.DialTimeout("tcp", addr, connectTimeout)
	}

	if err != nil {
		h.appConfig.LogWarn("[WS] Failed to dial upstream %s: %v", addr, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// Write the original request to upstream (including Upgrade headers)
	reqToSend := r.Clone(r.Context())

	// Set forwarded headers
	reqToSend.Header.Set("X-Forwarded-For", clientIP)
	reqToSend.Header.Set("X-Real-IP", clientIP)
	if application != nil {
		if application.Config.Advanced.ModifyHostHeader && application.Config.Advanced.HostHeaderValue != "" {
			hostValue := application.Config.Advanced.HostHeaderValue
			if hostValue == "$http_host" {
				hostValue = r.Host
			}
			reqToSend.Host = hostValue
			reqToSend.Header.Set("Host", hostValue)
		} else {
			reqToSend.Host = r.Host
			reqToSend.Header.Set("Host", r.Host)
		}
		if application.Config.Advanced.PassXForwardedHost {
			reqToSend.Header.Set("X-Forwarded-Host", r.Host)
		}
		if application.Config.Advanced.PassXForwardedProto {
			proto := "http"
			if r.TLS != nil {
				proto = "https"
			}
			reqToSend.Header.Set("X-Forwarded-Proto", proto)
		}
	}

	if err := reqToSend.Write(upstreamConn); err != nil {
		h.appConfig.LogWarn("[WS] Failed to write request to upstream: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the response from upstream to verify 101 Switching Protocols
	upstreamBuf := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamBuf, reqToSend)
	if err != nil {
		h.appConfig.LogWarn("[WS] Failed to read upstream response: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Not upgraded — return the response as-is
		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
		return
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		h.appConfig.LogWarn("[WS] ResponseWriter does not support hijacking")
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		h.appConfig.LogWarn("[WS] Hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	// Write the 101 response back to client
	if err := resp.Write(clientConn); err != nil {
		h.appConfig.LogWarn("[WS] Failed to write 101 to client: %v", err)
		return
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Upstream
	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, clientBuf)
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Upstream → Client
	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamBuf)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}
