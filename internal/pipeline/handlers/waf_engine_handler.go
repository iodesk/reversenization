package handlers

import (
	"fmt"
	"strings"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
	"github.com/vibeswaf/waf/internal/waf"
)

type WAFEngineHandler struct {
	wafService *service.WAFService
	appCfg     *config.AppConfig
}

func NewWAFEngineHandler(wafService *service.WAFService) *WAFEngineHandler {
	return &WAFEngineHandler{
		wafService: wafService,
		appCfg:     config.GetAppConfig(),
	}
}

func (h *WAFEngineHandler) Handle(ctx *pipeline.Context) error {
	if ctx.IPRuleTerminal {
		h.appCfg.LogDebug("[WAF_ENGINE] Skipped: IP rule is terminal")
		ctx.AddTrace(pipeline.StageTrace{Stage: "waf_anomaly", Result: "SKIP"})
		return nil
	}

	if ctx.ShouldSkipModule("waf") {
		h.appCfg.LogDebug("[WAF_ENGINE] Skipped: ShouldSkipModule")
		ctx.AddTrace(pipeline.StageTrace{Stage: "waf_anomaly", Result: "SKIP"})
		return nil
	}

	if ctx.IsPhaseSkipped("waf") {
		h.appCfg.LogDebug("[WAF_ENGINE] Skipped: phase marked as skipped")
		ctx.AddTrace(pipeline.StageTrace{Stage: "waf_anomaly", Result: "SKIP"})
		return nil
	}

	result := h.wafService.DetectOnly(ctx)

	ctx.WAFStatus = result.AnomalyScore
	ctx.SetExtra("waf_rule_id", result.TriggerRule)
	ctx.SetExtra("waf_matched_rules", result.MatchedRules)

	if result.AnomalyScore > 0 {
		// Build detailed rule ID string from actual detection rules
		ruleID := h.buildRuleID(result)
		reason := h.buildReason(result)

		ctx.AddScore(pipeline.ScoreCategoryWAFAnomaly, ruleID, result.AnomalyScore)
		h.appCfg.LogDebug("[WAF_ENGINE] Contributed score=%d to risk scoring (%s)", result.AnomalyScore, reason)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:    "waf_anomaly",
			Score:    result.AnomalyScore,
			RuleID:   ruleID,
			Reason:   reason,
			Evidence: h.buildEvidence(result),
		})
	} else {
		ctx.AddTrace(pipeline.StageTrace{Stage: "waf_anomaly", Score: 0})
	}

	return nil
}

// buildRuleID returns a comma-separated list of detection rule IDs.
func (h *WAFEngineHandler) buildRuleID(result *waf.WAFResult) string {
	if len(result.MatchedRules) == 0 {
		return "owasp_crs:" + result.TriggerRule
	}
	ids := make([]string, 0, len(result.MatchedRules))
	for _, mr := range result.MatchedRules {
		ids = append(ids, fmt.Sprintf("%d", mr.RuleID))
	}
	return strings.Join(ids, ",")
}

// buildReason returns a human-readable reason with categories.
func (h *WAFEngineHandler) buildReason(result *waf.WAFResult) string {
	if len(result.MatchedRules) == 0 {
		return "OWASP CRS match"
	}
	categories := make(map[string]int)
	for _, mr := range result.MatchedRules {
		categories[mr.Category]++
	}
	parts := make([]string, 0, len(categories))
	for cat, count := range categories {
		parts = append(parts, fmt.Sprintf("%s(%d)", cat, count))
	}
	return strings.Join(parts, ",")
}

// buildEvidence returns detailed matched rules info for trace.
func (h *WAFEngineHandler) buildEvidence(result *waf.WAFResult) string {
	if len(result.MatchedRules) == 0 {
		return ""
	}
	parts := make([]string, 0, len(result.MatchedRules))
	for _, mr := range result.MatchedRules {
		parts = append(parts, fmt.Sprintf("#%d[%s]", mr.RuleID, mr.Category))
	}
	return strings.Join(parts, " ")
}
