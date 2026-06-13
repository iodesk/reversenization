package v1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/api/v1/handler"
	"github.com/vibeswaf/waf/internal/api/v1/middleware"
	"github.com/vibeswaf/waf/internal/cache"
	"github.com/vibeswaf/waf/internal/challenge"
	"github.com/vibeswaf/waf/internal/logger"
	"github.com/vibeswaf/waf/internal/pipeline"
	handlers "github.com/vibeswaf/waf/internal/pipeline/handlers"
	"github.com/vibeswaf/waf/internal/ratelimit"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/service"
)

type Router struct {
	ruleHandler          *handler.RuleHandler
	appHandler           *handler.AppHandler
	wafHandler           *handler.WAFHandler
	logHandler           *handler.LogHandler
	analyticsHandler     *handler.AnalyticsHandler
	healthHandler        *handler.HealthHandler
	rateLimitHandler     *handler.RateLimitHandler
	botPatternHandler    *handler.BotPatternHandler
	botIPRangeHandler    *handler.BotIPRangeHandler
	settingsHandler      *handler.SettingsHandler
	ipAccessHandler      *handler.IPAccessHandler
	ipReputationHandler  *handler.IPReputationHandler
	authHandler          *handler.AuthHandler
	performanceHandler   *handler.PerformanceHandler
	certificateHandler   *handler.CertificateHandler
	cacheHandler         *handler.CacheHandler
	authMiddleware       *middleware.AuthMiddleware
	rateLimitMiddleware  *middleware.RateLimitMiddleware
	botService           *service.BotDetectionService
	challengeStore       *challenge.Store
	challengeRegistry    *challenge.Registry
	logger               *logger.Clickhouse
}

func NewRouter(
	ruleService *service.RuleService,
	appService *service.AppService,
	wafService *service.WAFService,
	logger *logger.Clickhouse,
	p *pipeline.Pipeline,
	botPatternRepo *repository.BotPatternRepository,
	settingsRepo *repository.SettingsRepository,
	ipAccessService *service.IPAccessService,
	authService *service.AuthService,
	botService *service.BotDetectionService,
	maxmind *service.MaxMindService,
	rateLimitService *service.RateLimitService,
	certificateService *service.CertificateService,
	appConfig handler.AppConfig,
	decisionCache *cache.DecisionCache,
	challengeStore *challenge.Store,
	challengeRegistry *challenge.Registry,
	botIPRangeRepo *repository.BotIPRangeRepository,
	botIPRangeFetcher *service.BotIPRangeFetcher,
	ipReputationService *service.IPReputationService,
	floodProtector *ratelimit.FloodProtector,
	trustedHistory *handlers.TrustedHistoryScorer,
	settingsCache *service.SettingsCache,
) *Router {
	return &Router{
		ruleHandler:         handler.NewRuleHandler(ruleService, logger),
		appHandler:          handler.NewAppHandler(appService, rateLimitService),
		wafHandler:          handler.NewWAFHandler(wafService, appService, logger, p, maxmind, appConfig, floodProtector, trustedHistory),
		logHandler:          handler.NewLogHandler(logger),
		analyticsHandler:    handler.NewAnalyticsHandler(logger),
		healthHandler:       handler.NewHealthHandler(),
		rateLimitHandler:    handler.NewRateLimitHandler(settingsRepo, rateLimitService, logger),
		botPatternHandler:   handler.NewBotPatternHandler(botPatternRepo),
		botIPRangeHandler:   handler.NewBotIPRangeHandler(botIPRangeRepo, botIPRangeFetcher),
		settingsHandler:     handler.NewSettingsHandler(settingsRepo, wafService, rateLimitService, settingsCache),
		ipAccessHandler:     handler.NewIPAccessHandler(ipAccessService),
		ipReputationHandler: handler.NewIPReputationHandler(ipReputationService, maxmind),
		authHandler:         handler.NewAuthHandler(authService),
		performanceHandler:  handler.NewPerformanceHandler(),
		certificateHandler:  handler.NewCertificateHandler(certificateService),
		cacheHandler:        handler.NewCacheHandler(decisionCache),
		authMiddleware:      middleware.NewAuthMiddleware(authService),
		rateLimitMiddleware: middleware.NewRateLimitMiddleware(authService),
		botService:          botService,
		challengeStore:      challengeStore,
		challengeRegistry:   challengeRegistry,
		logger:              logger,
	}
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/health" {
		host := r.Host
		// Strip port if present
		if i := strings.LastIndex(host, ":"); i != -1 {
			host = host[:i]
		}
		isInternal := host == "" || host == "localhost" || host == "127.0.0.1"
		if isInternal {
			rt.healthHandler.Health(w, r)
		} else {
			rt.healthHandler.HealthForApp(w, r, rt.wafHandler.AppService())
		}
		return
	}

	if r.URL.Path == "/__waf_verify" {
		rt.handleWAFVerify(w, r)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		rt.setDashboardCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		rt.rateLimitMiddleware.Limit(rt.handleAPIRoutes)(w, r)
		return
	}

	rt.wafHandler.ServeHTTP(w, r)
}

func (rt *Router) handleAPIRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasPrefix(path, "/api/v1/auth") {
		rt.handleAuthRoutes(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/rules") {
		rt.authMiddleware.Authenticate(rt.handleRuleRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/apps") {
		rt.authMiddleware.Authenticate(rt.handleAppRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/logs") {
		rt.authMiddleware.Authenticate(rt.handleLogRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/rate-limit") {
		rt.authMiddleware.Authenticate(rt.handleRateLimitRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/bot-ip-ranges") {
		rt.authMiddleware.Authenticate(rt.handleBotIPRangeRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/bot-patterns") {
		rt.authMiddleware.Authenticate(rt.handleBotPatternRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/ip-reputation") {
		rt.authMiddleware.Authenticate(rt.handleIPReputationRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/settings") {
		rt.authMiddleware.Authenticate(rt.handleSettingsRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/analytics") {
		rt.authMiddleware.Authenticate(rt.handleAnalyticsRoutes)(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/certificates") {
		rt.authMiddleware.Authenticate(rt.handleCertificateRoutes)(w, r)
		return
	}

	if path == "/api/v1/performance/stats" && r.Method == http.MethodGet {
		rt.authMiddleware.Authenticate(rt.performanceHandler.GetStats)(w, r)
		return
	}

	if path == "/api/v1/cache/stats" && r.Method == http.MethodGet {
		rt.authMiddleware.Authenticate(func(w http.ResponseWriter, r *http.Request) {
			rt.cacheHandler.GetStats(w, r)
		})(w, r)
		return
	}

	http.NotFound(w, r)
}

func (rt *Router) handleRuleRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/rules/fields" && r.Method == http.MethodGet {
		rt.ruleHandler.GetFieldMetadata(w, r)
		return
	}

	if path == "/api/v1/rules/validate" && r.Method == http.MethodPost {
		rt.ruleHandler.ValidateExpression(w, r)
		return
	}

	if path == "/api/v1/rules/events" && r.Method == http.MethodGet {
		rt.ruleHandler.GetRuleEvents(w, r)
		return
	}

	if path == "/api/v1/rules/reorder" && r.Method == http.MethodPost {
		rt.ruleHandler.ReorderRules(w, r)
		return
	}

	if path == "/api/v1/rules" && r.Method == http.MethodPost {
		rt.ruleHandler.CreateRule(w, r)
		return
	}

	if path == "/api/v1/rules" && r.Method == http.MethodGet {
		rt.ruleHandler.ListRules(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/rules/") && r.Method == http.MethodGet {
		rt.ruleHandler.GetRule(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/rules/") && r.Method == http.MethodPut {
		rt.ruleHandler.UpdateRule(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/rules/") && r.Method == http.MethodDelete {
		rt.ruleHandler.DeleteRule(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleAppRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/apps" && r.Method == http.MethodPost {
		rt.appHandler.CreateApp(w, r)
		return
	}

	if path == "/api/v1/apps" && r.Method == http.MethodGet {
		rt.appHandler.ListApps(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/apps/") && r.Method == http.MethodGet && !strings.Contains(path[len("/api/v1/apps/"):], "/") {
		rt.appHandler.GetApp(w, r)
		return
	}

	if strings.HasSuffix(path, "/under-attack") && r.Method == http.MethodPut {
		rt.appHandler.ToggleUnderAttackMode(w, r)
		return
	}

	if strings.Contains(path, "/ip-access-rules") {
		rt.handleAppIPAccessRoutes(w, r)
		return
	}

	if strings.Contains(path, "/rules") {
		rt.handleAppRuleRoutes(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/apps/") && r.Method == http.MethodGet {
		rt.appHandler.GetApp(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/apps/") && r.Method == http.MethodPut {
		rt.appHandler.UpdateApp(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/apps/") && r.Method == http.MethodDelete {
		rt.appHandler.DeleteApp(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleAppIPAccessRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasSuffix(path, "/ip-access-rules") && r.Method == http.MethodGet {
		rt.ipAccessHandler.List(w, r)
		return
	}

	if strings.HasSuffix(path, "/ip-access-rules") && r.Method == http.MethodPost {
		rt.ipAccessHandler.Create(w, r)
		return
	}

	if strings.Contains(path, "/ip-access-rules/") && r.Method == http.MethodPut {
		rt.ipAccessHandler.Update(w, r)
		return
	}

	if strings.Contains(path, "/ip-access-rules/") && r.Method == http.MethodDelete {
		rt.ipAccessHandler.Delete(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleAppRuleRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasSuffix(path, "/rules/reorder") && r.Method == http.MethodPost {
		rt.ruleHandler.ReorderForApp(w, r)
		return
	}

	if strings.HasSuffix(path, "/rules") && r.Method == http.MethodGet {
		rt.ruleHandler.ListByApp(w, r)
		return
	}

	if strings.HasSuffix(path, "/rules") && r.Method == http.MethodPost {
		rt.ruleHandler.CreateForApp(w, r)
		return
	}

	if strings.Contains(path, "/rules/") && r.Method == http.MethodPut {
		rt.ruleHandler.UpdateForApp(w, r)
		return
	}

	if strings.Contains(path, "/rules/") && r.Method == http.MethodDelete {
		rt.ruleHandler.DeleteForApp(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleLogRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/logs" && r.Method == http.MethodGet {
		rt.logHandler.ListLogs(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleRateLimitRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/rate-limit" && r.Method == http.MethodGet {
		rt.rateLimitHandler.GetRateLimitConfig(w, r)
		return
	}

	if path == "/api/v1/rate-limit" && r.Method == http.MethodPut {
		rt.rateLimitHandler.UpdateRateLimitConfig(w, r)
		return
	}

	if path == "/api/v1/rate-limit/stats" && r.Method == http.MethodGet {
		rt.rateLimitHandler.GetStats(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleBotPatternRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/bot-patterns" && r.Method == http.MethodGet {
		rt.botPatternHandler.List(w, r)
		return
	}

	if path == "/api/v1/bot-patterns" && r.Method == http.MethodPost {
		rt.botPatternHandler.Create(w, r)
		return
	}

	if path == "/api/v1/bot-patterns/bulk-delete" && r.Method == http.MethodPost {
		rt.botPatternHandler.BulkDelete(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/bot-patterns/") && r.Method == http.MethodPut {
		rt.botPatternHandler.Update(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/bot-patterns/") && r.Method == http.MethodDelete {
		rt.botPatternHandler.Delete(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleBotIPRangeRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/bot-ip-ranges" && r.Method == http.MethodGet {
		rt.botIPRangeHandler.List(w, r)
		return
	}

	if path == "/api/v1/bot-ip-ranges" && r.Method == http.MethodPost {
		rt.botIPRangeHandler.Create(w, r)
		return
	}

	if strings.HasSuffix(path, "/sync") && r.Method == http.MethodPost {
		rt.botIPRangeHandler.Sync(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/bot-ip-ranges/") && r.Method == http.MethodPut {
		rt.botIPRangeHandler.Update(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/bot-ip-ranges/") && r.Method == http.MethodDelete {
		rt.botIPRangeHandler.Delete(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleIPReputationRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/ip-reputation/config" && r.Method == http.MethodGet {
		rt.ipReputationHandler.GetConfig(w, r)
		return
	}

	if path == "/api/v1/ip-reputation/config" && r.Method == http.MethodPut {
		rt.ipReputationHandler.UpdateConfig(w, r)
		return
	}

	if path == "/api/v1/ip-reputation/sync-spamhaus" && r.Method == http.MethodPost {
		rt.ipReputationHandler.SyncSpamhaus(w, r)
		return
	}

	if path == "/api/v1/ip-reputation" && r.Method == http.MethodGet {
		rt.ipReputationHandler.List(w, r)
		return
	}

	if path == "/api/v1/ip-reputation" && r.Method == http.MethodPost {
		rt.ipReputationHandler.Create(w, r)
		return
	}

	if path == "/api/v1/ip-reputation/bulk-delete" && r.Method == http.MethodPost {
		rt.ipReputationHandler.BulkDelete(w, r)
		return
	}

	if path == "/api/v1/ip-reputation/bulk-update-score" && r.Method == http.MethodPost {
		rt.ipReputationHandler.BulkUpdateScore(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/ip-reputation/") && r.Method == http.MethodPut {
		rt.ipReputationHandler.Update(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/ip-reputation/") && r.Method == http.MethodDelete {
		rt.ipReputationHandler.Delete(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleSettingsRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/settings/bot" && r.Method == http.MethodGet {
		rt.settingsHandler.GetBotConfig(w, r)
		return
	}

	if path == "/api/v1/settings/bot" && r.Method == http.MethodPut {
		rt.settingsHandler.UpdateBotConfig(w, r)
		return
	}

	if path == "/api/v1/settings/waf" && r.Method == http.MethodGet {
		rt.settingsHandler.GetWAFConfig(w, r)
		return
	}

	if path == "/api/v1/settings/waf" && r.Method == http.MethodPut {
		rt.settingsHandler.UpdateWAFConfig(w, r)
		return
	}

	if path == "/api/v1/settings/scoring" && r.Method == http.MethodGet {
		rt.settingsHandler.GetScoringConfig(w, r)
		return
	}

	if path == "/api/v1/settings/scoring" && r.Method == http.MethodPut {
		rt.settingsHandler.UpdateScoringConfig(w, r)
		return
	}

	if path == "/api/v1/settings/protocol-anomaly" && r.Method == http.MethodGet {
		rt.settingsHandler.GetProtocolAnomalyConfig(w, r)
		return
	}

	if path == "/api/v1/settings/protocol-anomaly" && r.Method == http.MethodPut {
		rt.settingsHandler.UpdateProtocolAnomalyConfig(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleAnalyticsRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/analytics/traffic" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetTrafficAnalytics(w, r)
		return
	}

	if path == "/api/v1/analytics/threats" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetTopThreats(w, r)
		return
	}

	if path == "/api/v1/analytics/insights" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetDashboardInsights(w, r)
		return
	}

	if path == "/api/v1/analytics/challenge-stats" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetChallengeStats(w, r)
		return
	}

	if path == "/api/v1/analytics/top-blocked-bots" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetTopBlockedBots(w, r)
		return
	}

	if path == "/api/v1/analytics/waf-stats" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetWAFStats(w, r)
		return
	}

	if path == "/api/v1/analytics/cache" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetCacheAnalytics(w, r)
		return
	}

	if path == "/api/v1/analytics/threat-intel/ips" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetThreatIPs(w, r)
		return
	}

	if path == "/api/v1/analytics/threat-intel/waf-rules" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetWAFRuleIntel(w, r)
		return
	}

	if path == "/api/v1/analytics/threat-intel/summary" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetThreatSummary(w, r)
		return
	}

	if path == "/api/v1/analytics/threat-intel/custom-rules" && r.Method == http.MethodGet {
		rt.analyticsHandler.GetCustomRuleIntel(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleAuthRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/auth/setup" && r.Method == http.MethodGet {
		rt.authHandler.NeedsSetup(w, r)
		return
	}

	if path == "/api/v1/auth/setup" && r.Method == http.MethodPost {
		rt.authHandler.Setup(w, r)
		return
	}

	if path == "/api/v1/auth/login" && r.Method == http.MethodPost {
		rt.authHandler.Login(w, r)
		return
	}

	if path == "/api/v1/auth/logout" && r.Method == http.MethodPost {
		rt.authHandler.Logout(w, r)
		return
	}

	if path == "/api/v1/auth/me" && r.Method == http.MethodGet {
		rt.authHandler.Me(w, r)
		return
	}

	if path == "/api/v1/auth/change-password" && r.Method == http.MethodPut {
		rt.authHandler.ChangePassword(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleCertificateRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/api/v1/certificates" && r.Method == http.MethodGet {
		rt.certificateHandler.ListCertificates(w, r)
		return
	}

	if path == "/api/v1/certificates/sync" && r.Method == http.MethodPost {
		rt.certificateHandler.SyncFromFilesystem(w, r)
		return
	}

	if path == "/api/v1/certificates/bulk-delete" && r.Method == http.MethodPost {
		rt.certificateHandler.BulkDeleteCertificates(w, r)
		return
	}

	if strings.HasSuffix(path, "/renew") && r.Method == http.MethodPost {
		rt.certificateHandler.RenewCertificate(w, r)
		return
	}

	if strings.HasSuffix(path, "/validate") && r.Method == http.MethodPost {
		rt.certificateHandler.ValidateCertificate(w, r)
		return
	}

	if strings.HasSuffix(path, "/auto-renew") && r.Method == http.MethodPut {
		rt.certificateHandler.ToggleAutoRenew(w, r)
		return
	}

	if strings.HasSuffix(path, "/logs") && r.Method == http.MethodGet {
		rt.certificateHandler.GetCertificateLogs(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/certificates/") && r.Method == http.MethodGet {
		rt.certificateHandler.GetCertificate(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/v1/certificates/") && r.Method == http.MethodDelete {
		rt.certificateHandler.DeleteCertificate(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (rt *Router) handleWAFVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		ChallengeID string                    `json:"challenge_id"`
		Answer      int                       `json:"answer"`
		Duration    int64                     `json:"duration"`
		Trajectory  []challenge.TrajectoryPoint `json:"trajectory"`
		Signals     challenge.ChallengeSignals  `json:"signals"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	data := rt.challengeStore.Get(req.ChallengeID)
	if data == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"ok":false,"error":"expired"}`))
		return
	}

	ct := rt.challengeRegistry.GetByType(data.Type)
	if ct == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Extract real client IP using trusted proxy walking.
	// Default: trust Cloudflare CF-Connecting-IP; fall back to walking X-Forwarded-For.
	ip := r.RemoteAddr
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		ip = strings.TrimSpace(cfIP)
	} else if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		// Walk from right to left; rightmost IP not in loopback is the real client.
		// OpenResty/nginx always appends client IP as first entry in XFF, so the
		// leftmost should be the actual client in our architecture.
		ip = strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip = host
		}
	}

	// Rate limit: block IPs that solve challenges too frequently
	if rt.challengeStore.IsSolveRateLimited(ip) {
		rt.logger.Log(logger.LogEntry{
			TS:     time.Now(),
			IP:     ip,
			Host:   r.Host,
			Path:   "/__waf_verify",
			UA:     r.UserAgent(),
			Action: "challenge_failed",
			Reason: "solve_rate_limited",
			Status: 403,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"ok":false,"error":"rate_limited"}`))
		return
	}

	meta := challenge.ValidateMeta{
		IP:       ip,
		UA:       r.UserAgent(),
		Duration: time.Duration(req.Duration) * time.Millisecond,
	}

	if !ct.Validate(data, req.Answer, meta) {
		attempts := rt.challengeStore.IncrementAttempts(req.ChallengeID)
		maxRetries := rt.challengeStore.MaxRetries()
		remaining := maxRetries - attempts
		if remaining < 0 {
			remaining = 0
		}
		if attempts >= maxRetries {
			rt.challengeStore.Delete(req.ChallengeID)
			rt.logger.Log(logger.LogEntry{
				TS:     time.Now(),
				IP:     ip,
				Host:   r.Host,
				Path:   "/__waf_verify",
				UA:     r.UserAgent(),
				Action: "challenge_failed",
				Reason: "max_attempts_exceeded",
				Status: 403,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"ok":false,"error":"invalid","remaining":%d}`, remaining)
		return
	}

	rt.challengeStore.Delete(req.ChallengeID)

	// Record solve for rate limiting
	rt.challengeStore.RecordSolve(ip)

	// Compute trust level from trajectory + signals
	botCfg := rt.botService.GetConfig()
	tlCfg := challenge.TrustLevelConfig{
		Level0Max:         botCfg.TrustLevels.Level0Max,
		Level1Max:         botCfg.TrustLevels.Level1Max,
		Level2Max:         botCfg.TrustLevels.Level2Max,
		Reductions:        botCfg.TrustLevels.Reductions,
		MinPoints:         10,
		SpeedVarianceMin:  0.5,
		StraightnessMax:   0.99,
		JitterMin:         0.5,
		TimingVarianceMin: 2.0,
		FirstInteractMin:  200,
		AccelVarianceMin:  0.3,
		PauseRequired:     true,
		PauseMinMs:        40,
	}

	trajectoryScore := challenge.AnalyzeTrajectory(req.Trajectory, tlCfg)
	signalsScore := challenge.AnalyzeSignals(req.Signals, tlCfg)
	trustLevel := challenge.ComputeTrustLevel(trajectoryScore, signalsScore, tlCfg)

	rt.logger.Log(logger.LogEntry{
		TS:     time.Now(),
		IP:     ip,
		Host:   r.Host,
		Path:   "/__waf_verify",
		UA:     r.UserAgent(),
		Action: "challenge_solved",
		Reason: fmt.Sprintf("duration:%dms|trust_level:%d|t_score:%.2f|s_score:%.2f", req.Duration, trustLevel, trajectoryScore, signalsScore),
		Status: 200,
	})

	secret := os.Getenv("WAF_SECRET")
	if secret == "" {
		secret = "fallback_secret"
	}

	ua := r.UserAgent()
	timestamp := time.Now().Unix()
	payload := fmt.Sprintf("%s:%s:%d:%d", ip, ua, timestamp, trustLevel)

	hm := hmac.New(sha256.New, []byte(secret))
	hm.Write([]byte(payload))
	signature := hex.EncodeToString(hm.Sum(nil))
	token := fmt.Sprintf("%s.%d.%d", signature, timestamp, trustLevel)

	cookieMaxAge := botCfg.ChallengeDuration

	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name:     "ok",
		Value:    token,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func (rt *Router) setDashboardCORS(w http.ResponseWriter, r *http.Request) {
	allowedOrigins := strings.Split(getEnvOrDefault("CORS_ALLOW_ORIGIN", "*"), ",")
	requestOrigin := r.Header.Get("Origin")

	originAllowed := false
	for _, origin := range allowedOrigins {
		trimmedOrigin := strings.TrimSpace(origin)
		if trimmedOrigin == "*" || trimmedOrigin == requestOrigin {
			if trimmedOrigin == "*" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
			}
			originAllowed = true
			break
		}
	}

	if !originAllowed && len(allowedOrigins) > 0 {
		w.Header().Set("Access-Control-Allow-Origin", strings.TrimSpace(allowedOrigins[0]))
	}

	w.Header().Set("Access-Control-Allow-Methods", getEnvOrDefault("CORS_ALLOW_METHODS", "GET, POST, PUT, DELETE, OPTIONS"))
	w.Header().Set("Access-Control-Allow-Headers", getEnvOrDefault("CORS_ALLOW_HEADERS", "Content-Type, Authorization, Cookie"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Max-Age", getEnvOrDefault("CORS_MAX_AGE", "3600"))
}
