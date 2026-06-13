package handlers

import (
	"time"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/ratelimit"
	"github.com/vibeswaf/waf/internal/service"
)

type FloodHandler struct {
	flood            *ratelimit.FloodProtector
	rateLimitService *service.RateLimitService
	appCfg           *config.AppConfig
}

func NewFloodHandler(flood *ratelimit.FloodProtector, rateLimitService *service.RateLimitService) *FloodHandler {
	return &FloodHandler{
		flood:            flood,
		rateLimitService: rateLimitService,
		appCfg:           config.GetAppConfig(),
	}
}

func (h *FloodHandler) getConfig() model.RateLimitConfig {
	if h.rateLimitService != nil {
		return h.rateLimitService.GetConfig()
	}
	return model.DefaultRateLimitConfig()
}

func (h *FloodHandler) Handle(ctx *pipeline.Context) error {
	h.appCfg.LogDebug("[FLOOD] Enter handler ip=%s hardDecision=%v", ctx.ClientIP, ctx.HardDecision)

	if ctx.HardDecision {
		h.appCfg.LogDebug("[FLOOD] Skipped: HardDecision already set")
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: "SKIP"})
		return nil
	}

	if ctx.ShouldSkipModule("flood") {
		h.appCfg.LogDebug("[FLOOD] Skipped: module disabled by rule")
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: "SKIP"})
		return nil
	}

	if ctx.IPRuleTerminal {
		h.appCfg.LogDebug("[FLOOD] Skipped: IP rule is terminal")
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: "SKIP"})
		return nil
	}

	if ctx.ChallengePassed {
		h.appCfg.LogDebug("[FLOOD] Skipped: challenge already passed")
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: "SKIP"})
		return nil
	}

	ip := ctx.ClientIP
	cfg := h.getConfig()

	if h.flood.IsChallenged(ip) {
		h.appCfg.LogInfo("[FLOOD] IP %s is under flood challenge penalty", ip)
		decision := pipeline.NewDecision("challenge", "flood", "flood_penalty_active")
		ctx.AddDecision(decision)
		ctx.HardDecision = true
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: "CHALLENGE", Reason: "flood_penalty_active"})
		return nil
	}

	if cfg.Attack.Enabled && !h.flood.CheckAttackLimit(ip) {
		action := cfg.Attack.Action
		if action == "" {
			action = "block"
		}
		penalty := time.Duration(cfg.Attack.ChallengeSec) * time.Second
		if penalty <= 0 {
			penalty = 5 * time.Minute
		}

		h.appCfg.LogInfo("[FLOOD] Attack flood limit exceeded ip=%s action=%s", ip, action)
		h.flood.SetChallenge(ip, penalty)
		if h.rateLimitService != nil {
			h.rateLimitService.RecordAttackHit()
		}
		decision := pipeline.NewDecision(action, "flood", "attack_flood_exceeded")
		ctx.AddDecision(decision)
		ctx.HardDecision = true
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: toResult(action), Reason: "attack_flood_exceeded"})
		return nil
	}

	if cfg.Error.Enabled && !h.flood.CheckErrorLimit(ip) {
		action := cfg.Error.Action
		if action == "" {
			action = "challenge"
		}
		penalty := time.Duration(cfg.Error.ChallengeSec) * time.Second
		if penalty <= 0 {
			penalty = 5 * time.Minute
		}

		h.appCfg.LogInfo("[FLOOD] Error flood limit exceeded ip=%s action=%s", ip, action)
		h.flood.SetChallenge(ip, penalty)
		if h.rateLimitService != nil {
			h.rateLimitService.RecordErrorHit()
		}
		decision := pipeline.NewDecision(action, "flood", "error_flood_exceeded")
		ctx.AddDecision(decision)
		ctx.HardDecision = true
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: toResult(action), Reason: "error_flood_exceeded"})
		return nil
	}

	if cfg.Basic.Enabled && !h.flood.CheckBasicAccess(ip) {
		action := cfg.Basic.Action
		if action == "" {
			action = "challenge"
		}
		penalty := time.Duration(cfg.Basic.ChallengeSec) * time.Second
		if penalty <= 0 {
			penalty = 10 * time.Minute
		}

		h.appCfg.LogInfo("[FLOOD] Basic access limit exceeded ip=%s action=%s", ip, action)
		h.flood.SetChallenge(ip, penalty)
		decision := pipeline.NewDecision(action, "flood", "basic_access_limit")
		ctx.AddDecision(decision)
		ctx.HardDecision = true
		ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: toResult(action), Reason: "basic_access_limit"})
		return nil
	}

	h.appCfg.LogDebug("[FLOOD] Passed ip=%s", ip)
	ctx.AddTrace(pipeline.StageTrace{Stage: "flood", Result: "PASS"})
	return nil
}
