package handlers

import (
	"fmt"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
)

type IPAccessHandler struct {
	ipAccessService *service.IPAccessService
	appCfg          *config.AppConfig
}

func NewIPAccessHandler(ipAccessService *service.IPAccessService) *IPAccessHandler {
	return &IPAccessHandler{
		ipAccessService: ipAccessService,
		appCfg:          config.GetAppConfig(),
	}
}

func (h *IPAccessHandler) Handle(ctx *pipeline.Context) error {
	appID := "default"
	if ctx.AppID != "" {
		appID = ctx.AppID
	}

	h.appCfg.LogDebug("[IP_ACCESS] Checking IP=%s app_id=%s", ctx.ClientIP, appID)

	ipRule, err := h.ipAccessService.CheckIP(appID, ctx.ClientIP)
	if err != nil {
		h.appCfg.LogError("[IP_ACCESS] Failed to check IP: %v", err)
		ctx.AddTrace(pipeline.StageTrace{Stage: "ip_access_rule", Result: "ERROR", Reason: err.Error()})
		return nil
	}

	if ipRule == nil || !ipRule.Enabled {
		ctx.AddTrace(pipeline.StageTrace{Stage: "ip_access_rule", Result: "NO_MATCH"})
		return nil
	}

	h.appCfg.LogInfo("[IP_ACCESS] Rule matched: %s (Action: %s, IP: %s)",
		ipRule.Description, ipRule.Action, ctx.ClientIP)

	decision := pipeline.NewDecision(
		ipRule.Action,
		"ip_access_rule",
		fmt.Sprintf("ip_access_rule:%s", ipRule.Description),
	)
	ctx.AddDecision(decision)

	ctx.IPRuleTerminal = true
	ctx.SetExtra("matched_ip_rule_id", ipRule.ID)
	ctx.SetExtra("matched_ip_rule_description", ipRule.Description)
	ctx.SetExtra("matched_ip_rule_action", ipRule.Action)
	ctx.SetExtra("matched_ip_rule_ip_range", ipRule.IPRange)

	ctx.AddTrace(pipeline.StageTrace{
		Stage:  "ip_access_rule",
		Result: toResult(ipRule.Action),
		RuleID: fmt.Sprintf("%d", ipRule.ID),
		Reason: ipRule.Description,
	})

	// Mark as hard decision — Phase 2 scoring will be skipped.
	// Allow is also a hard decision: "I trust this, fast-track to proxy."
	ctx.HardDecision = true

	h.appCfg.LogInfo("[IP_ACCESS] Terminal action set - bypassing subsequent security checks")
	return nil
}
