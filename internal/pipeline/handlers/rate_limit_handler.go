package handlers

import (
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
)

type RateLimitHandler struct {
	rateLimitService *service.RateLimitService
	appCfg           *config.AppConfig
}

func NewRateLimitHandler(rateLimitService *service.RateLimitService) *RateLimitHandler {
	return &RateLimitHandler{
		rateLimitService: rateLimitService,
		appCfg:           config.GetAppConfig(),
	}
}

func (h *RateLimitHandler) Handle(ctx *pipeline.Context) error {
	h.appCfg.LogDebug("[RATE_LIMIT] Enter handler ip=%s hardDecision=%v", ctx.ClientIP, ctx.HardDecision)

	if ctx.HardDecision {
		h.appCfg.LogDebug("[RATE_LIMIT] Skipped: HardDecision already set")
		ctx.AddTrace(pipeline.StageTrace{Stage: "rate_limit", Result: "SKIP"})
		return nil
	}

	if ctx.ShouldSkipModule("rate_limit") {
		h.appCfg.LogDebug("[RATE_LIMIT] Skipped: module disabled by rule")
		ctx.AddTrace(pipeline.StageTrace{Stage: "rate_limit", Result: "SKIP"})
		return nil
	}

	if ctx.IPRuleTerminal {
		h.appCfg.LogDebug("[RATE_LIMIT] Skipped: IP rule is terminal")
		ctx.AddTrace(pipeline.StageTrace{Stage: "rate_limit", Result: "SKIP"})
		return nil
	}
	if ctx.ChallengePassed {
		h.appCfg.LogDebug("[RATE_LIMIT] Skipped: challenge already passed")
		ctx.AddTrace(pipeline.StageTrace{Stage: "rate_limit", Result: "SKIP"})
		return nil
	}

	appID := "default"
	if ctx.AppID != "" {
		appID = ctx.AppID
	}

	allowed, action := h.rateLimitService.Allow(appID, ctx.ClientIP, ctx.Request.UserAgent())
	if allowed {
		h.appCfg.LogDebug("[RATE_LIMIT] Allowed app=%s ip=%s", appID, ctx.ClientIP)
		ctx.AddTrace(pipeline.StageTrace{Stage: "rate_limit", Result: "PASS"})
		return nil
	}

	if action == "" {
		action = "block"
	}

	h.appCfg.LogInfo("[RATE_LIMIT] %s app=%s ip=%s", action, appID, ctx.ClientIP)

	decision := pipeline.NewDecision(action, "rate_limit", "rate_limit_exceeded")
	ctx.AddDecision(decision)
	ctx.HardDecision = true

	ctx.AddTrace(pipeline.StageTrace{
		Stage:  "rate_limit",
		Result: toResult(action),
		Reason: "rate_limit_exceeded",
	})

	return nil
}
