package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/vibeswaf/waf/internal/cache"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
)

const trustedHistoryKeyPrefix = "th:"
const trustedHistoryTTL = 24 * time.Hour

type TrustedHistoryScorer struct {
	getConfig func() *model.ScoringConfig
	redis     *cache.RedisClient
	appCfg    *config.AppConfig
}

func NewTrustedHistoryScorer(getConfig func() *model.ScoringConfig, redis *cache.RedisClient) *TrustedHistoryScorer {
	return &TrustedHistoryScorer{
		getConfig: getConfig,
		redis:     redis,
		appCfg:    config.GetAppConfig(),
	}
}

func (h *TrustedHistoryScorer) Handle(ctx *pipeline.Context) error {
	if ctx.HardDecision {
		return nil
	}

	cfg := h.getConfig()
	if cfg == nil {
		return nil
	}

	threshold := cfg.Trust.TrustedHistoryThreshold
	reduction := cfg.Trust.TrustedHistory
	if threshold <= 0 || reduction == 0 {
		return nil
	}

	if !h.redis.IsEnabled() {
		return nil
	}

	key := trustedHistoryKeyPrefix + ctx.ClientIP
	count, err := h.redis.GetInt(context.Background(), key)
	if err != nil {
		// No history yet for this IP
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "trusted_history",
			Result: "NEW",
			Reason: "No history yet",
		})
		return nil
	}

	if count >= int64(threshold) {
		ctx.AddScore(pipeline.ScoreCategoryTrust, "trusted_history", reduction)
		h.appCfg.LogDebug("[TRUST] Trusted history: ip=%s count=%d threshold=%d reduction=%d", ctx.ClientIP, count, threshold, reduction)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "trusted_history",
			Score:  reduction,
			Reason: fmt.Sprintf("%d clean requests (threshold: %d)", count, threshold),
		})
	} else {
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "trusted_history",
			Result: "PENDING",
			Reason: fmt.Sprintf("%d / %d clean requests", count, threshold),
		})
	}

	return nil
}

// RecordCleanRequest increments the clean request counter for an IP.
// Called by waf_handler after action=allow.
func (h *TrustedHistoryScorer) RecordCleanRequest(ip string) {
	if !h.redis.IsEnabled() {
		return
	}
	key := trustedHistoryKeyPrefix + ip
	h.redis.Incr(context.Background(), key, trustedHistoryTTL)
}

// ResetHistory resets the trusted history counter for an IP.
// Called when an IP gets blocked or challenged.
func (h *TrustedHistoryScorer) ResetHistory(ip string) {
	if !h.redis.IsEnabled() {
		return
	}
	key := trustedHistoryKeyPrefix + ip
	h.redis.Del(context.Background(), key)
}
