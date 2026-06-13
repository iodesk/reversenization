package handlers

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/repository"
)

type protocolAnomalyState struct {
	rules map[string]int
}

type ProtocolAnomalyHandler struct {
	getScoringConfig func() *model.ScoringConfig
	settingsRepo     *repository.SettingsRepository
	appCfg           *config.AppConfig

	state  unsafe.Pointer // *protocolAnomalyState
	mu     sync.Mutex
	stopCh chan struct{}
}

func NewProtocolAnomalyHandler(getScoringConfig func() *model.ScoringConfig, settingsRepo *repository.SettingsRepository) *ProtocolAnomalyHandler {
	h := &ProtocolAnomalyHandler{
		getScoringConfig: getScoringConfig,
		settingsRepo:     settingsRepo,
		appCfg:           config.GetAppConfig(),
		stopCh:           make(chan struct{}),
	}

	initial := h.loadState()
	atomic.StorePointer(&h.state, unsafe.Pointer(initial))
	go h.autoReload()

	return h
}

func (h *ProtocolAnomalyHandler) loadState() *protocolAnomalyState {
	cfg, err := h.settingsRepo.GetProtocolAnomalyConfig()
	if err != nil {
		h.appCfg.LogWarn("[PROTOCOL_ANOMALY] Failed to load config: %v", err)
		cfg = model.DefaultProtocolAnomalyConfig()
	}
	return &protocolAnomalyState{rules: cfg.Rules}
}

func (h *ProtocolAnomalyHandler) autoReload() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-ticker.C:
			next := h.loadState()
			atomic.StorePointer(&h.state, unsafe.Pointer(next))
		}
	}
}

func (h *ProtocolAnomalyHandler) getState() *protocolAnomalyState {
	return (*protocolAnomalyState)(atomic.LoadPointer(&h.state))
}

func (h *ProtocolAnomalyHandler) ruleScore(name string) int {
	st := h.getState()
	if v, ok := st.rules[name]; ok {
		return v
	}
	return 0
}

func (h *ProtocolAnomalyHandler) Handle(ctx *pipeline.Context) error {
	if ctx.HardDecision {
		ctx.AddTrace(pipeline.StageTrace{Stage: "protocol_anomaly", Result: "SKIP"})
		return nil
	}

	if ctx.ChallengePassed {
		ctx.AddTrace(pipeline.StageTrace{Stage: "protocol_anomaly", Result: "SKIP"})
		return nil
	}

	if ctx.ShouldSkipModule("protocol_anomaly") {
		ctx.AddTrace(pipeline.StageTrace{Stage: "protocol_anomaly", Result: "SKIP"})
		return nil
	}

	if ctx.IsPhaseSkipped("protocol_anomaly") {
		ctx.AddTrace(pipeline.StageTrace{Stage: "protocol_anomaly", Result: "SKIP"})
		return nil
	}

	var score int
	var reasons []string

	headerScore, headerReasons := h.checkHeaderInconsistency(ctx)
	score += headerScore
	reasons = append(reasons, headerReasons...)

	cookieScore, cookieReasons := h.checkCookieAnomaly(ctx)
	score += cookieScore
	reasons = append(reasons, cookieReasons...)

	ja4Score, ja4Reasons := h.checkJA4Anomaly(ctx)
	score += ja4Score
	reasons = append(reasons, ja4Reasons...)

	if score > 0 {
		h.appCfg.LogDebug("[PROTOCOL_ANOMALY] Contributed score=%d for ip=%s", score, ctx.ClientIP)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "protocol_anomaly",
			Score:  score,
			Reason: joinReasons(reasons),
		})
	} else {
		ctx.AddTrace(pipeline.StageTrace{Stage: "protocol_anomaly", Score: 0})
	}

	return nil
}

func (h *ProtocolAnomalyHandler) checkHeaderInconsistency(ctx *pipeline.Context) (int, []string) {
	r := ctx.Request
	var score int
	var reasons []string

	// HTTP/2 should not have Connection header
	if r.ProtoMajor >= 2 && r.Header.Get("Connection") != "" {
		s := h.ruleScore("http2_connection_header")
		if s > 0 {
			ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "http2_connection_header", s)
			score += s
			reasons = append(reasons, "HTTP/2 Connection header")
		}
	}

	// Content-Type on GET/HEAD request (no body expected)
	method := strings.ToUpper(r.Method)
	if (method == "GET" || method == "HEAD") && r.Header.Get("Content-Type") != "" {
		s := h.ruleScore("content_type_no_body")
		if s > 0 {
			ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "content_type_no_body", s)
			score += s
			reasons = append(reasons, "Content-Type on bodyless request")
		}
	}

	// Accept: text/html but path is clearly an API/data endpoint
	accept := r.Header.Get("Accept")
	path := ctx.Normalized.Path
	if accept != "" && strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
		if isAPIPath(path) {
			s := h.ruleScore("accept_path_mismatch")
			if s > 0 {
				ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "accept_path_mismatch", s)
				score += s
				reasons = append(reasons, "Accept/path mismatch")
			}
		}
	}

	// Sec-Fetch-Dest: document but path is asset/API
	secFetchDest := r.Header.Get("Sec-Fetch-Dest")
	if secFetchDest == "document" {
		if isAssetOrAPIPath(path) {
			s := h.ruleScore("sec_fetch_dest_mismatch")
			if s > 0 {
				ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "sec_fetch_dest_mismatch", s)
				score += s
				reasons = append(reasons, "Sec-Fetch-Dest mismatch")
			}
		}
	}

	// Upgrade-Insecure-Requests on non-navigate
	if r.Header.Get("Upgrade-Insecure-Requests") == "1" {
		secFetchMode := r.Header.Get("Sec-Fetch-Mode")
		if secFetchMode != "" && secFetchMode != "navigate" {
			s := h.ruleScore("upgrade_non_navigate")
			if s > 0 {
				ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "upgrade_non_navigate", s)
				score += s
				reasons = append(reasons, "Upgrade-Insecure-Requests non-navigate")
			}
		}
	}

	// Transfer-Encoding and Content-Length both present (request smuggling indicator)
	if r.Header.Get("Transfer-Encoding") != "" && r.Header.Get("Content-Length") != "" {
		s := h.ruleScore("te_cl_conflict")
		if s > 0 {
			ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "te_cl_conflict", s)
			score += s
			reasons = append(reasons, "TE/CL conflict")
		}
	}

	// Multiple Host headers (smuggling/spoofing)
	if hosts := r.Header.Values("Host"); len(hosts) > 1 {
		s := h.ruleScore("multiple_host_headers")
		if s > 0 {
			ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "multiple_host_headers", s)
			score += s
			reasons = append(reasons, "Multiple Host headers")
		}
	}

	return score, reasons
}

func (h *ProtocolAnomalyHandler) checkCookieAnomaly(ctx *pipeline.Context) (int, []string) {
	r := ctx.Request
	var score int
	var reasons []string

	// Check for invalid challenge cookie (present but HMAC doesn't match)
	cookie, err := r.Cookie("ok")
	if err == nil && cookie.Value != "" {
		if !h.isValidChallengeFormat(cookie.Value) {
			s := h.ruleScore("malformed_challenge_cookie")
			if s > 0 {
				ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "malformed_challenge_cookie", s)
				score += s
				reasons = append(reasons, "Malformed challenge cookie")
			}
		} else if h.isCookieTimestampFuture(cookie.Value) {
			s := h.ruleScore("future_cookie_timestamp")
			if s > 0 {
				ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "future_cookie_timestamp", s)
				score += s
				reasons = append(reasons, "Future cookie timestamp")
			}
		}
	}

	// Suspicious: many cookies on a path that shouldn't have them
	cookieHeader := r.Header.Get("Cookie")
	if cookieHeader != "" {
		cookieCount := strings.Count(cookieHeader, "=")
		path := ctx.Normalized.Path
		if cookieCount > 10 && (path == "/" || path == "") {
			referer := r.Header.Get("Referer")
			if referer == "" {
				s := h.ruleScore("excessive_cookies_no_referer")
				if s > 0 {
					ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "excessive_cookies_no_referer", s)
					score += s
					reasons = append(reasons, "Excessive cookies without referer")
				}
			}
		}
	}

	return score, reasons
}

func (h *ProtocolAnomalyHandler) isValidChallengeFormat(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	if len(parts[0]) != 32 && len(parts[0]) != 64 {
		return false
	}
	_, err := strconv.ParseInt(parts[1], 10, 64)
	return err == nil
}
func (h *ProtocolAnomalyHandler) isCookieTimestampFuture(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	return timestamp > time.Now().Unix()+60
}
func (h *ProtocolAnomalyHandler) checkJA4Anomaly(ctx *pipeline.Context) (int, []string) {
	r := ctx.Request
	var score int
	var reasons []string

	ja4 := r.Header.Get("X-JA4")
	ja4h := r.Header.Get("X-JA4H")

	// Store in metadata for logging/visibility
	if ja4 != "" {
		ctx.SetExtra("ja4", ja4)
	}
	if ja4h != "" {
		ctx.SetExtra("ja4h", ja4h)
	}

	ua := strings.ToLower(ctx.Normalized.UA)
	isBrowserUA := strings.Contains(ua, "mozilla") && (strings.Contains(ua, "chrome") || strings.Contains(ua, "safari") || strings.Contains(ua, "firefox"))
	isBotUA := strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider") || strings.Contains(ua, "curl") || strings.Contains(ua, "python") || strings.Contains(ua, "go-http")

	// Rule 1: Browser UA + HTTP/1.0
	if isBrowserUA && r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		s := h.ruleScore("browser_ua_http10")
		if s > 0 {
			ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "browser_ua_http10", s)
			score += s
			reasons = append(reasons, "Browser UA with HTTP/1.0")
		}
	}

	// Rule 2: Browser UA + Old TLS (JA4 starts with t10 or t11)
	if isBrowserUA && ja4 != "" && len(ja4) >= 3 {
		tlsVer := ja4[1:3]
		if tlsVer == "10" || tlsVer == "11" {
			s := h.ruleScore("ja4_old_tls_browser_ua")
			if s > 0 {
				ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "ja4_old_tls_browser_ua", s)
				score += s
				reasons = append(reasons, "Old TLS with browser UA")
			}
		}
	}

	// Rule 3: Browser UA + JA4 Empty (HTTPS request but no JA4 — should not happen)
	if isBrowserUA && ja4 == "" && r.TLS != nil {
		s := h.ruleScore("browser_ua_ja4_empty")
		if s > 0 {
			ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "browser_ua_ja4_empty", s)
			score += s
			reasons = append(reasons, "Missing JA4 on TLS browser request")
		}
	}

	// Rule 4: Bot UA + Browser-like JA4
	if isBotUA && ja4 != "" && len(ja4) >= 7 {
		if ja4[3] == 'd' {
			cipherCountStr := ja4[4:6]
			if cipherCount, err := strconv.Atoi(cipherCountStr); err == nil && cipherCount >= 12 {
				s := h.ruleScore("bot_ua_browser_ja4")
				if s > 0 {
					ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "bot_ua_browser_ja4", s)
					score += s
					reasons = append(reasons, "Bot UA with browser-like JA4")
				}
			}
		}
	}

	// Rule 5: Browser UA + Simple/Bot JA4
	if isBrowserUA && ja4 != "" && len(ja4) >= 7 {
		if ja4[3] == 'd' {
			cipherCountStr := ja4[4:6]
			if cipherCount, err := strconv.Atoi(cipherCountStr); err == nil && cipherCount <= 4 {
				s := h.ruleScore("browser_ua_simple_ja4")
				if s > 0 {
					ctx.AddScore(pipeline.ScoreCategoryProtocolAnomaly, "browser_ua_simple_ja4", s)
					score += s
					reasons = append(reasons, "Browser UA with simple JA4")
				}
			}
		}
	}

	return score, reasons
}

func isAPIPath(path string) bool {
	apiPrefixes := []string{"/api/", "/graphql", "/rest/", "/v1/", "/v2/"}
	apiSuffixes := []string{".json", ".xml", ".yaml", ".proto"}
	for _, prefix := range apiPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for _, suffix := range apiSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isAssetOrAPIPath(path string) bool {
	if isAPIPath(path) {
		return true
	}
	assetSuffixes := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".woff", ".woff2", ".ttf", ".ico", ".webp", ".avif",
	}
	for _, suffix := range assetSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
