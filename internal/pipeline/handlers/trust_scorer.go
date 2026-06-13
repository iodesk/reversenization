package handlers

import (
	"fmt"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
)

type TrustScorer struct {
	getConfig  func() *model.ScoringConfig
	botService *service.BotDetectionService
	appCfg     *config.AppConfig
}

func NewTrustScorer(getConfig func() *model.ScoringConfig, botService *service.BotDetectionService) *TrustScorer {
	return &TrustScorer{
		getConfig:  getConfig,
		botService: botService,
		appCfg:     config.GetAppConfig(),
	}
}

func (h *TrustScorer) Handle(ctx *pipeline.Context) error {
	if ctx.HardDecision {
		return nil
	}

	cfg := h.getConfig()
	if cfg == nil {
		return nil
	}

	if !ctx.ChallengePassed {
		ctx.AddTrace(pipeline.StageTrace{Stage: "trust", Result: "SKIP"})
		return nil
	}

	trustLevel := ctx.TrustLevel

	// Get trust reduction from bot config trust levels
	botCfg := h.botService.GetConfig()
	reductions := botCfg.TrustLevels.Reductions

	var reduction int
	if trustLevel >= 0 && trustLevel <= 3 {
		reduction = reductions[trustLevel]
	}

	if reduction != 0 {
		rule := fmt.Sprintf("challenge_trust_level_%d", trustLevel)
		ctx.AddScore(pipeline.ScoreCategoryTrust, rule, reduction)
		h.appCfg.LogDebug("[TRUST] Applied trust_level=%d reduction=%d for ip=%s", trustLevel, reduction, ctx.ClientIP)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "trust",
			Score:  reduction,
			Reason: fmt.Sprintf("Challenge Trust Level %d", trustLevel),
		})
	} else {
		h.appCfg.LogDebug("[TRUST] trust_level=%d reduction=0 for ip=%s (solved but suspicious)", trustLevel, ctx.ClientIP)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "trust",
			Score:  0,
			Reason: fmt.Sprintf("Challenge Trust Level %d (no reduction)", trustLevel),
		})
	}

	return nil
}
