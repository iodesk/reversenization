package handlers

import (
	"context"
	"time"

	"github.com/vibeswaf/waf/internal/cache"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
)

const stableSessionKeyPrefix = "ss:"
const stableSessionTTL = 4 * time.Hour

type StableSessionScorer struct {
	getConfig func() *model.ScoringConfig
	redis     *cache.RedisClient
	appCfg    *config.AppConfig
}

func NewStableSessionScorer(getConfig func() *model.ScoringConfig, redis *cache.RedisClient) *StableSessionScorer {
	return &StableSessionScorer{
		getConfig: getConfig,
		redis:     redis,
		appCfg:    config.GetAppConfig(),
	}
}

func (h *StableSessionScorer) Handle(ctx *pipeline.Context) error {
	if ctx.HardDecision {
		return nil
	}

	cfg := h.getConfig()
	if cfg == nil {
		return nil
	}

	reduction := cfg.Trust.StableSession
	if reduction == 0 {
		return nil
	}

	if !h.redis.IsEnabled() {
		return nil
	}

	fingerprint := ctx.HTTPFingerprint
	if fingerprint == "" {
		return nil
	}

	key := stableSessionKeyPrefix + ctx.ClientIP
	stored, err := h.redis.Get(context.Background(), key)

	if err != nil {
		// No stored fingerprint yet — record it, no reduction yet
		h.redis.Set(context.Background(), key, fingerprint, stableSessionTTL)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "stable_session",
			Result: "NEW",
			Reason: "First visit — fingerprint recorded",
		})
		return nil
	}

	if stored == fingerprint {
		// Fingerprint matches — consistent session, apply reduction
		// Refresh TTL on match to keep active sessions trusted
		h.redis.Set(context.Background(), key, fingerprint, stableSessionTTL)
		ctx.AddScore(pipeline.ScoreCategoryTrust, "stable_session", reduction)
		h.appCfg.LogDebug("[TRUST] Stable session: ip=%s reduction=%d", ctx.ClientIP, reduction)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "stable_session",
			Score:  reduction,
			Reason: "Consistent session fingerprint",
		})
	} else {
		// Fingerprint changed — update to new fingerprint, no reduction
		h.redis.Set(context.Background(), key, fingerprint, stableSessionTTL)
		h.appCfg.LogDebug("[TRUST] Stable session changed: ip=%s", ctx.ClientIP)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "stable_session",
			Result: "CHANGED",
			Reason: "Fingerprint changed — no trust reduction",
		})
	}

	return nil
}
