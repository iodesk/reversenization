package handlers

import (
	"fmt"

	"github.com/vibeswaf/waf/internal/cache"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
)

type RulesEngineHandler struct {
	ruleService   *service.RuleService
	decisionCache *cache.DecisionCache
	appCfg        *config.AppConfig
}

func NewRulesEngineHandler(ruleService *service.RuleService, decisionCache *cache.DecisionCache) *RulesEngineHandler {
	return &RulesEngineHandler{
		ruleService:   ruleService,
		decisionCache: decisionCache,
		appCfg:        config.GetAppConfig(),
	}
}

func (h *RulesEngineHandler) Handle(ctx *pipeline.Context) error {
	h.appCfg.LogDebug("[RULES] RulesEngineHandler called for IP=%s", ctx.ClientIP)

	if ctx.IPRuleTerminal {
		h.appCfg.LogDebug("[RULES] Skipped: IP rule is terminal")
		ctx.AddTrace(pipeline.StageTrace{Stage: "custom_rules", Result: "SKIP"})
		return nil
	}
	if ctx.ChallengePassed {
		h.appCfg.LogDebug("[RULES] Skipped: challenge already passed")
		ctx.AddTrace(pipeline.StageTrace{Stage: "custom_rules", Result: "SKIP"})
		return nil
	}

	appID := "default"
	if ctx.AppID != "" {
		appID = ctx.AppID
	}

	rules, err := h.ruleService.LoadMergedRules(appID)
	if err != nil {
		h.appCfg.LogError("[RULES] Failed to load rules for app %s: %v", appID, err)
		ctx.AddTrace(pipeline.StageTrace{Stage: "custom_rules", Result: "ERROR", Reason: err.Error()})
		return nil
	}

	h.appCfg.LogDebug("[RULES] Loaded %d rules for app %s", len(rules), appID)

	for _, r := range rules {
		if !r.Enabled {
			continue
		}

		matched, err := h.ruleService.EvaluateRule(r, ctx)
		if err != nil {
			h.appCfg.LogError("[RULES] Failed to evaluate rule '%s' (ID:%d): %v", r.Name, r.ID, err)
			continue
		}

		if !matched {
			continue
		}

		h.appCfg.LogInfo("[RULES] Rule '%s' (ID:%d, Priority:%d) matched: %s",
			r.Name, r.ID, r.Priority, r.Action)

		switch r.Action {
		case "allow", "block", "challenge":
			reason := fmt.Sprintf("rule:%d:%s", r.ID, r.Name)
			decision := pipeline.NewDecision(r.Action, "custom_rule", reason)
			ctx.AddDecision(decision)
			h.recordRuleMatch(ctx, r.ID, r.Name, r.Action, r.Scope)
			h.decisionCache.Set(ctx, r.Action, "custom_rule", reason)

			ctx.AddTrace(pipeline.StageTrace{
				Stage:  "custom_rules",
				Result: toResult(r.Action),
				RuleID: fmt.Sprintf("%d", r.ID),
				Reason: r.Name,
			})

			// Mark as hard decision so Phase 2 is skipped.
			// Allow is also hard: "I trust this, fast-track to proxy."
			ctx.HardDecision = true
			return nil

		case "log":
			h.appCfg.LogDebug("[RULES] Log match for rule '%s', continuing", r.Name)
			h.recordRuleMatch(ctx, r.ID, r.Name, r.Action, r.Scope)

		case "skip":
			decision := pipeline.NewSkipDecision("custom_rule", r.SkipModules)
			ctx.AddDecision(decision)
			ctx.AddSkipModules(r.SkipModules)
			h.appCfg.LogDebug("[RULES] Skipping modules %v by rule '%s'", r.SkipModules, r.Name)
			h.recordRuleMatch(ctx, r.ID, r.Name, r.Action, r.Scope)

		default:
			h.appCfg.LogDebug("[RULES] Unknown action '%s' for rule '%s'", r.Action, r.Name)
			h.recordRuleMatch(ctx, r.ID, r.Name, r.Action, r.Scope)
		}
	}

	ctx.AddTrace(pipeline.StageTrace{Stage: "custom_rules", Result: "PASS"})
	return nil
}

func (h *RulesEngineHandler) recordRuleMatch(ctx *pipeline.Context, id int, name, action, scope string) {
	ctx.SetExtra("matched_rule_id", id)
	ctx.SetExtra("matched_rule_name", name)
	ctx.SetExtra("matched_rule_action", action)
	ctx.SetExtra("matched_rule_scope", scope)

	var matched []map[string]interface{}
	if existing, ok := ctx.GetExtra("matched_rules"); ok {
		matched, _ = existing.([]map[string]interface{})
	}
	matched = append(matched, map[string]interface{}{
		"id":     id,
		"name":   name,
		"action": action,
		"scope":  scope,
	})
	ctx.SetExtra("matched_rules", matched)
}

func BuildRuleReasons(matchedRules []map[string]interface{}) []string {
	reasons := make([]string, 0, len(matchedRules))
	for _, r := range matchedRules {
		id, _ := r["id"].(int)
		name, _ := r["name"].(string)
		reasons = append(reasons, fmt.Sprintf("rule:%d:%s", id, name))
	}
	return reasons
}
