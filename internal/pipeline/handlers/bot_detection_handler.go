package handlers

import (
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
)

type BotDetectionHandler struct {
	botService *service.BotDetectionService
	appCfg     *config.AppConfig
}

func NewBotDetectionHandler(botService *service.BotDetectionService) *BotDetectionHandler {
	return &BotDetectionHandler{
		botService: botService,
		appCfg:     config.GetAppConfig(),
	}
}

func (h *BotDetectionHandler) Handle(ctx *pipeline.Context) error {
	h.appCfg.LogDebug("[BOT] BotDetectionHandler called for IP=%s", ctx.ClientIP)

	if ctx.IPRuleTerminal {
		h.appCfg.LogDebug("[BOT] Skipped: IP rule is terminal")
		ctx.AddTrace(pipeline.StageTrace{Stage: "bot_detection", Result: "SKIP"})
		return nil
	}
	if ctx.ChallengePassed {
		h.appCfg.LogDebug("[BOT] Skipped: challenge already passed")
		ctx.AddTrace(pipeline.StageTrace{Stage: "bot_detection", Result: "SKIP"})
		return nil
	}

	if ctx.ShouldSkipModule("bot") {
		h.appCfg.LogDebug("[BOT] Skipped: ShouldSkipModule")
		ctx.AddTrace(pipeline.StageTrace{Stage: "bot_detection", Result: "SKIP"})
		return nil
	}

	if ctx.IsPhaseSkipped("bot") {
		h.appCfg.LogDebug("[BOT] Skipped: phase marked as skipped")
		ctx.AddTrace(pipeline.StageTrace{Stage: "bot_detection", Result: "SKIP"})
		return nil
	}

	botCfg := h.botService.GetConfig()
	threshold := botCfg.Threshold
	action := botCfg.Action

	score := h.botService.AnalyzeRequest(ctx, threshold, action)

	h.appCfg.LogDebug("[BOT] score=%d threshold=%d", score.TotalScore, threshold)

	ctx.SetExtra("bot_score", score.TotalScore)
	ctx.SetExtra("bot_reasons", service.FormatScoreReasons(score))

	ctx.AddScore(pipeline.ScoreCategoryBotDetection, "bot_composite", score.TotalScore)
	h.appCfg.LogDebug("[BOT] Contributed score=%d to risk scoring", score.TotalScore)

	ctx.AddTrace(pipeline.StageTrace{
		Stage:    "bot_detection",
		Score:    score.TotalScore,
		Reason:   service.FormatScoreReasons(score),
		Evidence: score.Evidence,
	})

	return nil
}
