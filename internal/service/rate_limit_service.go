package service

import (
	"sync/atomic"
	"time"
	"unsafe"

	appcfg "github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/domain/app"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/ratelimit"
	"github.com/vibeswaf/waf/internal/repository"
)

// globalRLState is swapped atomically on reload — zero lock on hot path.
type globalRLState struct {
	cfg     model.RateLimitConfig
	limiter *ratelimit.RateLimiter
}

type RateLimitService struct {
	settingsRepo *repository.SettingsRepository
	appService   *AppService

	// state is read via atomic load on every request — zero lock contention.
	state unsafe.Pointer // *globalRLState

	// hit counters per profile type — incremented atomically
	hitsBasic  int64
	hitsAttack int64
	hitsError  int64

	reloadInterval time.Duration
	stopCh         chan struct{}
}

func NewRateLimitService(settingsRepo *repository.SettingsRepository, appService *AppService) *RateLimitService {
	s := &RateLimitService{
		settingsRepo:   settingsRepo,
		appService:     appService,
		reloadInterval: 30 * time.Second,
		stopCh:         make(chan struct{}),
	}

	cfg, err := settingsRepo.GetRateLimitConfig()
	if err != nil {
		appcfg.GetAppConfig().LogWarn("[RateLimit] Failed to load config, using defaults: %v", err)
		cfg = model.DefaultRateLimitConfig()
	}

	limiter := ratelimit.NewRateLimiter()
	atomic.StorePointer(&s.state, unsafe.Pointer(&globalRLState{cfg: cfg, limiter: limiter}))

	go s.autoReload()
	return s
}

func (s *RateLimitService) getState() *globalRLState {
	return (*globalRLState)(atomic.LoadPointer(&s.state))
}

// GetConfig returns the cached rate limit config via an atomic read.
// Used by the flood handler to avoid a DB query on the request path.
func (s *RateLimitService) GetConfig() model.RateLimitConfig {
	return s.getState().cfg
}

func (s *RateLimitService) autoReload() {
	ticker := time.NewTicker(s.reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			cfg, err := s.settingsRepo.GetRateLimitConfig()
			if err != nil {
				appcfg.GetAppConfig().LogWarn("[RateLimit] Failed to reload config: %v", err)
				continue
			}

			old := s.getState()

			// Create fresh limiter — old entries drain via TTL in the old one.
			limiter := ratelimit.NewRateLimiter()
			next := &globalRLState{cfg: cfg, limiter: limiter}
			atomic.StorePointer(&s.state, unsafe.Pointer(next))

			if old != nil && old.limiter != nil {
				old.limiter.Stop()
			}
		}
	}
}

// Stop terminates the autoReload goroutine and the current limiter.
func (s *RateLimitService) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	if st := s.getState(); st != nil && st.limiter != nil {
		st.limiter.Stop()
	}
}

// resolveProfile returns the effective rate limit profile for an app.
// Per-app config overrides global when UseGlobalRateLimit=false.
func (s *RateLimitService) resolveProfile(appID string) (count int, duration int, action string, enabled bool) {
	globalCfg := s.getState().cfg
	basic := globalCfg.Basic

	count = basic.Count
	duration = basic.Duration
	action = basic.Action
	enabled = basic.Enabled

	if appID == "default" || s.appService == nil {
		return
	}

	appCfg, err := s.appService.GetApp(appID)
	if err != nil || appCfg == nil {
		return
	}

	if appCfg.Config.UseGlobalRateLimit {
		return
	}

	var profile *app.RateLimitProfile
	for i := range appCfg.Config.RateLimits {
		rl := &appCfg.Config.RateLimits[i]
		if rl.Type == "Standard" || rl.Type == "" || profile == nil {
			profile = rl
			if rl.Type == "Standard" {
				break
			}
		}
	}

	if profile != nil && profile.Count > 0 && profile.Duration > 0 {
		count = profile.Count
		duration = profile.Duration
		action = profile.Action
		enabled = true
	}

	return
}

// Allow returns (allowed bool, action string).
// action is the configured response when rate limit is exceeded.
func (s *RateLimitService) Allow(appID, clientIP, userAgent string) (bool, string) {
	count, duration, action, enabled := s.resolveProfile(appID)

	if !enabled || count <= 0 || duration <= 0 {
		appcfg.GetAppConfig().LogDebug("[RATE_LIMIT_SVC] Disabled for app=%s (enabled=%v count=%d duration=%d)", appID, enabled, count, duration)
		return true, ""
	}

	appcfg.GetAppConfig().LogDebug("[RATE_LIMIT_SVC] Checking app=%s ip=%s limit=%d/%ds", appID, clientIP, count, duration)

	refillRate := float64(count) / float64(max(duration, 1))
	key := ratelimit.GenerateKey(clientIP, userAgent)
	bucketKey := appID + ":" + key

	st := s.getState()
	allowed := st.limiter.Allow(bucketKey, count, refillRate)

	if !allowed {
		appcfg.GetAppConfig().LogInfo("[RATE_LIMIT] blocked app=%s ip=%s (limit: %d req/%ds action=%s)",
			appID, clientIP, count, duration, action)
		atomic.AddInt64(&s.hitsBasic, 1)
	}

	return allowed, action
}

// InvalidateCache stops the current limiter and creates a fresh one.
// appID is accepted for interface compatibility but all entries are reset.
func (s *RateLimitService) InvalidateCache(appID string) {
	old := s.getState()
	cfg := old.cfg

	limiter := ratelimit.NewRateLimiter()
	next := &globalRLState{cfg: cfg, limiter: limiter}
	atomic.StorePointer(&s.state, unsafe.Pointer(next))

	if old.limiter != nil {
		old.limiter.Stop()
	}
}

// RecordAttackHit increments the attack hit counter (called by flood handler).
func (s *RateLimitService) RecordAttackHit() {
	atomic.AddInt64(&s.hitsAttack, 1)
}

// RecordErrorHit increments the error hit counter (called by flood handler).
func (s *RateLimitService) RecordErrorHit() {
	atomic.AddInt64(&s.hitsError, 1)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
