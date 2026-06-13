package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vibeswaf/waf/internal/cache"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/scoring"
)

const (
	// maxDNSCacheSize is the hard cap on in-memory DNS verification cache entries (fallback).
	maxDNSCacheSize = 50_000
	// dnsCacheTTL is how long a DNS verification result is cached.
	dnsCacheTTL = 7 * 24 * time.Hour
	// dnsVerifyTimeout is the max time allowed for synchronous DNS verification.
	dnsVerifyTimeout = 700 * time.Millisecond
)

// botState is the hot-path read data swapped atomically on reload.
type botState struct {
	patterns  []model.BotPattern
	whitelist []model.BotWhitelist
	botConfig model.BotConfig
	scorer    *scoring.Scorer
}

// dnsResult caches a three-step bot DNS verification result.
type dnsResult struct {
	result verifyResult
	expiry time.Time
}

type BotDetectionService struct {
	botPatternRepo *repository.BotPatternRepository
	settingsRepo   *repository.SettingsRepository
	maxmind        *MaxMindService
	appCfg         *config.AppConfig
	ipRangeFetcher *BotIPRangeFetcher
	redis          *cache.RedisClient

	// state is read via atomic load on every request — zero lock contention.
	state unsafe.Pointer // *botState

	reloadInterval time.Duration

	// dnsCache is the in-memory fallback when Redis is disabled.
	dnsMu    sync.RWMutex
	dnsCache map[string]dnsResult

	stopCh chan struct{}
}

func NewBotDetectionService(
	botPatternRepo *repository.BotPatternRepository,
	settingsRepo *repository.SettingsRepository,
	maxmind *MaxMindService,
	ipRangeFetcher *BotIPRangeFetcher,
	redis *cache.RedisClient,
) *BotDetectionService {
	s := &BotDetectionService{
		botPatternRepo: botPatternRepo,
		settingsRepo:   settingsRepo,
		maxmind:        maxmind,
		appCfg:         config.GetAppConfig(),
		ipRangeFetcher: ipRangeFetcher,
		redis:          redis,
		reloadInterval: 10 * time.Second,
		dnsCache:       make(map[string]dnsResult),
		stopCh:         make(chan struct{}),
	}

	initial := s.loadState()
	atomic.StorePointer(&s.state, unsafe.Pointer(initial))

	go s.autoReload()
	go s.dnsCacheCleanup()

	return s
}

func (s *BotDetectionService) loadState() *botState {
	patterns, err := s.botPatternRepo.GetAllPatterns()
	if err != nil {
		s.appCfg.LogWarn("[BotDetection] Failed to load patterns: %v", err)
		patterns = nil
	}

	// Precompute lowercase patterns once so the hot path avoids ToLower per request.
	for i := range patterns {
		patterns[i].PatternLower = strings.ToLower(patterns[i].Pattern)
	}

	whitelist, err := s.botPatternRepo.GetWhitelist()
	if err != nil {
		s.appCfg.LogWarn("[BotDetection] Failed to load whitelist: %v", err)
		whitelist = nil
	}

	botConfig, err := s.settingsRepo.GetBotConfig()
	if err != nil {
		s.appCfg.LogWarn("[BotDetection] Failed to load bot config, using default: %v", err)
		botConfig = model.DefaultBotConfig()
	}

	sc := scoring.NewScorerWithConfig(botConfig)

	// First load during init → startup log. Subsequent reloads → debug only.
	if atomic.LoadPointer(&s.state) == nil {
		s.appCfg.LogStartup("BotDetection: %d patterns loaded", len(patterns))
	} else {
		s.appCfg.LogDebug("[BotDetection] Reloaded %d patterns, %d whitelist entries", len(patterns), len(whitelist))
	}
	return &botState{
		patterns:  patterns,
		whitelist: whitelist,
		botConfig: botConfig,
		scorer:    sc,
	}
}

func (s *BotDetectionService) getState() *botState {
	return (*botState)(atomic.LoadPointer(&s.state))
}

func (s *BotDetectionService) autoReload() {
	ticker := time.NewTicker(s.reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			next := s.loadState()
			atomic.StorePointer(&s.state, unsafe.Pointer(next))
		}
	}
}

func (s *BotDetectionService) dnsCacheCleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			s.dnsMu.Lock()
			for ip, r := range s.dnsCache {
				if now.After(r.expiry) {
					delete(s.dnsCache, ip)
				}
			}
			s.dnsMu.Unlock()
		}
	}
}

// Stop terminates background goroutines.
func (s *BotDetectionService) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *BotDetectionService) GetConfig() model.BotConfig {
	return s.getState().botConfig
}

func (s *BotDetectionService) IsWhitelisted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, entry := range s.getState().whitelist {
		_, ipNet, err := net.ParseCIDR(entry.IPRange)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *BotDetectionService) AnalyzeRequest(ctx *pipeline.Context, threshold int, action string) *model.BotScore {
	s.appCfg.LogDebug("[BOT] AnalyzeRequest IP=%s UA=%s", ctx.ClientIP, ctx.Request.UserAgent())

	if s.IsWhitelisted(ctx.ClientIP) {
		score := &model.BotScore{TotalScore: -40}
		score.Add("whitelisted_ip", -40)
		return score
	}

	st := s.getState()

	thresholdVal := st.botConfig.Threshold
	actionVal := st.botConfig.Action
	if threshold > 0 {
		thresholdVal = threshold
	}
	if action != "" {
		actionVal = action
	}

	// Use geo data already set by waf_handler to avoid a second MaxMind lookup.
	s.analyzeBehavior(ctx, st)

	headerScore := st.scorer.AnalyzeHeaders(ctx)
	uaScore := st.scorer.AnalyzeUserAgent(ctx.Request.UserAgent(), st.patterns)
	refererScore := st.scorer.AnalyzeReferer(ctx.Request.Header.Get("Referer"), st.patterns)

	s.appCfg.LogDebug("[BOT] headerScore=%d uaScore=%d refererScore=%d",
		headerScore.TotalScore, uaScore.TotalScore, refererScore.TotalScore)

	if s.isKnownBotUA(ctx.Request.UserAgent(), st.patterns) {
		ctx.IsKnownBot = true
	} else {
		ctx.IsKnownBot = false
	}

	finalScore := st.scorer.CombineScores(headerScore, uaScore, refererScore)
	finalScore.Action = st.scorer.DetermineAction(finalScore.TotalScore, thresholdVal, actionVal)

	s.appCfg.LogDebug("[BOT] finalScore=%d threshold=%d action=%s", finalScore.TotalScore, thresholdVal, finalScore.Action)

	if finalScore.Metadata == nil {
		return finalScore
	}

	potentialGoodBot, ok := finalScore.Metadata["potential_good_bot"].(string)
	if !ok {
		return finalScore
	}

	// Get good bot trust value from scoring config (configurable, not absolute)
	goodBotTrust := -5
	if scoringCfg, err := s.settingsRepo.GetScoringConfig(); err == nil {
		goodBotTrust = scoringCfg.Trust.GoodBot
	}

	verifyIP, _ := finalScore.Metadata["verify_ip"].(bool)
	patternScore, _ := finalScore.Metadata["pattern_score"].(int)
	s.appCfg.LogDebug("[BOT] Potential good bot: %s verifyIP=%v score=%d patternScore=%d", potentialGoodBot, verifyIP, finalScore.TotalScore, patternScore)

	if verifyIP {
		result := s.verifyBotIPCached(ctx.ClientIP, potentialGoodBot)
		if result.verified {
			// All three steps passed — apply trust reduction.
			finalScore.TotalScore = 0
			finalScore.Action = ""
			finalScore.Reasons = nil
			finalScore.Add("verified_good_bot:"+potentialGoodBot, goodBotTrust)
			finalScore.Evidence = result.evidence
			ctx.IsKnownBot = true
			ctx.BotType = "good_bot"
			s.appCfg.LogInfo("[BOT] Verified good bot: %s IP=%s trust=%d", potentialGoodBot, ctx.ClientIP, goodBotTrust)
		} else {
			// Penalise using the pattern's own score.
			// Score 0 means the user considers this bot non-threatening even if fake —
			// no penalty added, just no trust reduction granted.
			// forward_dns and reverse_dns failures both use the same pattern score;
			// the distinction is logged for audit but does not change the penalty.
			if patternScore > 0 {
				finalScore.Add("fake_bot:"+potentialGoodBot+":"+result.failedStep, patternScore)
				finalScore.Action = st.scorer.DetermineAction(finalScore.TotalScore, thresholdVal, actionVal)
			}
			finalScore.Evidence = result.evidence
			s.appCfg.LogWarn("[BOT] Fake bot: UA=%s IP=%s step=%s penalty=%d", ctx.Request.UserAgent(), ctx.ClientIP, result.failedStep, patternScore)
		}
	} else {
		if finalScore.TotalScore <= 5 {
			finalScore.TotalScore = 0
			finalScore.Action = ""
			finalScore.Reasons = nil
			finalScore.Add("good_bot:"+potentialGoodBot, goodBotTrust)
			ctx.IsKnownBot = true
			ctx.BotType = "good_bot"
			s.appCfg.LogInfo("[BOT] Good bot consistent headers: %s trust=%d", potentialGoodBot, goodBotTrust)
		} else {
			finalScore.Add("suspicious_good_bot:"+potentialGoodBot, patternScore)
			finalScore.Action = st.scorer.DetermineAction(finalScore.TotalScore, thresholdVal, actionVal)
			s.appCfg.LogWarn("[BOT] Suspicious good bot: UA=%s score=%d", ctx.Request.UserAgent(), finalScore.TotalScore)
		}
	}

	return finalScore
}

// analyzeBehavior uses geo data already present on the context to avoid
// a second MaxMind lookup per request.
func (s *BotDetectionService) analyzeBehavior(ctx *pipeline.Context, st *botState) {
	ua := ctx.Request.UserAgent()
	acceptLang := ctx.Request.Header.Get("Accept-Language")

	if acceptLang != "" {
		country := ctx.Country
		if country == "" && s.maxmind != nil {
			if geoResult, err := s.maxmind.Lookup(ctx.ClientIP); err == nil {
				country = geoResult.CountryCode
			}
		}
		if country != "" {
			primaryLang := extractPrimaryLanguage(acceptLang)
			if !isLanguageMatchCountry(primaryLang, country) {
				ctx.GeoLangMismatch = true
			}
		}
	}

	if ua != "" {
		isKnownBrowser := isKnownBrowserUA(ua)
		isKnownBot := s.isKnownBotUA(ua, st.patterns)
		if !isKnownBrowser && !isKnownBot {
			ctx.UnknownBrowserBot = true
		}
	}
}

func (s *BotDetectionService) isKnownBotUA(ua string, patterns []model.BotPattern) bool {
	uaLower := strings.ToLower(ua)
	for _, pattern := range patterns {
		if !pattern.Enabled {
			continue
		}
		if pattern.PatternType == "good_bot" || pattern.PatternType == "bad_bot" {
			patternLower := pattern.PatternLower
			if patternLower == "" {
				patternLower = strings.ToLower(pattern.Pattern)
			}
			if strings.Contains(uaLower, patternLower) {
				return true
			}
		}
	}
	return false
}

// verifyResult holds the outcome of a full three-step bot DNS verification.
type verifyResult struct {
	verified     bool
	failedStep   string // "ip_range_miss", "reverse_dns", "forward_dns"
	hostname     string // matched hostname from reverse DNS
	evidence     string // human-readable step-by-step result
}

// verifyBotIPCached checks Redis first, then in-memory fallback.
// On cache miss, performs synchronous DNS verification (max 2s timeout)
// and stores the result in Redis (7d TTL).
func (s *BotDetectionService) verifyBotIPCached(ip, botPattern string) verifyResult {
	cacheKey := "bot_dns:" + ip + ":" + botPattern

	// Try Redis first
	if s.redis != nil && s.redis.IsEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		val, err := s.redis.Get(ctx, cacheKey)
		cancel()
		if err == nil && val != "" {
			return parseVerifyResult(val)
		}
	} else {
		// Fallback: in-memory cache
		s.dnsMu.RLock()
		r, ok := s.dnsCache[cacheKey]
		s.dnsMu.RUnlock()
		if ok && time.Now().Before(r.expiry) {
			return r.result
		}
	}

	// Cache miss — synchronous DNS verification with timeout
	result := s.verifyBotIPWithTimeout(ip, botPattern)

	// Store in Redis
	if s.redis != nil && s.redis.IsEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_ = s.redis.Set(ctx, cacheKey, serializeVerifyResult(result), dnsCacheTTL)
		cancel()
	} else {
		// Fallback: in-memory
		s.dnsMu.Lock()
		if len(s.dnsCache) < maxDNSCacheSize {
			s.dnsCache[cacheKey] = dnsResult{
				result: result,
				expiry: time.Now().Add(dnsCacheTTL),
			}
		}
		s.dnsMu.Unlock()
	}

	return result
}

// verifyBotIPWithTimeout wraps verifyBotIP with a deadline.
// Returns optimistic result on timeout.
func (s *BotDetectionService) verifyBotIPWithTimeout(ip, botPattern string) verifyResult {
	type resultCh struct {
		r verifyResult
	}
	ch := make(chan resultCh, 1)
	go func() {
		ch <- resultCh{r: s.verifyBotIP(ip, botPattern)}
	}()

	select {
	case res := <-ch:
		return res.r
	case <-time.After(dnsVerifyTimeout):
		s.appCfg.LogWarn("[BOT] DNS verify timeout (%v): IP=%s pattern=%s", dnsVerifyTimeout, ip, botPattern)
		return verifyResult{verified: true, evidence: "dns_verify:TIMEOUT"}
	}
}

// serializeVerifyResult encodes a verifyResult as a compact string for Redis.
func serializeVerifyResult(r verifyResult) string {
	v := "0"
	if r.verified {
		v = "1"
	}
	return v + "|" + r.failedStep + "|" + r.evidence
}

// parseVerifyResult decodes a Redis-stored string back into verifyResult.
func parseVerifyResult(s string) verifyResult {
	parts := strings.SplitN(s, "|", 3)
	if len(parts) < 3 {
		return verifyResult{verified: true, evidence: "cache:CORRUPT"}
	}
	return verifyResult{
		verified:   parts[0] == "1",
		failedStep: parts[1],
		evidence:   parts[2],
	}
}

func (s *BotDetectionService) verifyBotIP(ip string, botPattern string) verifyResult {
	// Step 1 — Fast path: known IP prefix ranges (no DNS needed)
	if s.ipRangeFetcher != nil && s.ipRangeFetcher.Contains(ip) {
		s.appCfg.LogInfo("[BOT] Verified via IP range: IP=%s pattern=%s", ip, botPattern)
		return verifyResult{verified: true, evidence: "ip_range:PASS"}
	}

	// Step 2 — Reverse DNS: IP → hostname
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		s.appCfg.LogDebug("[BOT] Reverse DNS failed for IP=%s: %v", ip, err)
		return verifyResult{verified: false, failedStep: "reverse_dns", evidence: "ip_range:MISS→rdns:FAIL(no PTR)"}
	}

	botPatternLower := strings.ToLower(botPattern)
	var matchedHostname string
	for _, name := range names {
		nameLower := strings.ToLower(name)
		if hostnameMatchesBot(nameLower, botPatternLower) {
			matchedHostname = name
			break
		}
	}

	if matchedHostname == "" {
		s.appCfg.LogWarn("[BOT] Reverse DNS hostname does not match bot pattern: IP=%s pattern=%s hostnames=%v", ip, botPattern, names)
		return verifyResult{verified: false, failedStep: "reverse_dns", evidence: "ip_range:MISS→rdns:FAIL(no match)"}
	}

	// Step 3 — Forward DNS: hostname → IPs (must include the original IP)
	forwardIPs, err := net.LookupHost(matchedHostname)
	if err != nil || len(forwardIPs) == 0 {
		s.appCfg.LogWarn("[BOT] Forward DNS failed: hostname=%s err=%v", matchedHostname, err)
		return verifyResult{verified: false, failedStep: "forward_dns", hostname: matchedHostname, evidence: "ip_range:MISS→rdns:PASS→fdns:FAIL(resolve error)"}
	}

	for _, fwdIP := range forwardIPs {
		if fwdIP == ip {
			s.appCfg.LogInfo("[BOT] Verified via double DNS: IP=%s hostname=%s", ip, matchedHostname)
			return verifyResult{verified: true, hostname: matchedHostname, evidence: "ip_range:MISS→rdns:PASS→fdns:PASS"}
		}
	}

	s.appCfg.LogWarn("[BOT] Forward DNS IP mismatch: IP=%s hostname=%s resolved=%v", ip, matchedHostname, forwardIPs)
	return verifyResult{verified: false, failedStep: "forward_dns", hostname: matchedHostname, evidence: "ip_range:MISS→rdns:PASS→fdns:FAIL(ip mismatch)"}
}

// hostnameMatchesBot checks whether a reverse-DNS hostname belongs to a known bot domain.
func hostnameMatchesBot(hostname, botPatternLower string) bool {
	switch {
	case strings.Contains(botPatternLower, "googlebot"):
		return strings.Contains(hostname, "googlebot.com") || strings.Contains(hostname, "google.com")
	case strings.Contains(botPatternLower, "bingbot"):
		return strings.Contains(hostname, "search.msn.com")
	case strings.Contains(botPatternLower, "yandex"):
		return strings.Contains(hostname, "yandex.com") ||
			strings.Contains(hostname, "yandex.net") ||
			strings.Contains(hostname, "yandex.ru")
	case strings.Contains(botPatternLower, "baiduspider"):
		return strings.Contains(hostname, "baidu.com") || strings.Contains(hostname, "baidu.jp")
	}
	return false
}

func extractPrimaryLanguage(acceptLang string) string {
	if acceptLang == "" {
		return ""
	}
	parts := strings.Split(acceptLang, ",")
	if len(parts) > 0 {
		lang := strings.TrimSpace(parts[0])
		if idx := strings.IndexAny(lang, "-;"); idx > 0 {
			return strings.ToLower(lang[:idx])
		}
		return strings.ToLower(lang)
	}
	return ""
}

func isLanguageMatchCountry(lang, country string) bool {
	if lang == "" || country == "" {
		return true
	}
	commonMismatches := map[string][]string{
		"zh": {"US", "GB", "DE", "FR"},
		"ru": {"US", "GB", "DE", "FR"},
		"ar": {"US", "GB", "DE", "FR"},
	}
	if countries, exists := commonMismatches[lang]; exists {
		for _, c := range countries {
			if c == country {
				return false
			}
		}
	}
	return true
}

func isKnownBrowserUA(ua string) bool {
	if ua == "" {
		return false
	}
	uaLower := strings.ToLower(ua)
	knownBrowsers := []string{
		"mozilla/5.0", "chrome/", "safari/", "firefox/",
		"edge/", "opera/", "msie", "trident/",
	}
	for _, browser := range knownBrowsers {
		if strings.Contains(uaLower, browser) {
			return true
		}
	}
	return false
}

func FormatScoreReasons(score *model.BotScore) string {
	if len(score.Reasons) == 0 {
		return ""
	}
	var parts []string
	for _, reason := range score.Reasons {
		parts = append(parts, fmt.Sprintf("%s:%+d", reason.Rule, reason.Score))
	}
	return strings.Join(parts, ", ")
}
