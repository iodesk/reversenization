package handlers

import (
	"strconv"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/service"
)

type IPReputationScorer struct {
	getScoringConfig func() *model.ScoringConfig
	ipRepService     *service.IPReputationService
	appCfg           *config.AppConfig
}

func NewIPReputationScorer(getScoringConfig func() *model.ScoringConfig, ipRepService *service.IPReputationService) *IPReputationScorer {
	return &IPReputationScorer{
		getScoringConfig: getScoringConfig,
		ipRepService:     ipRepService,
		appCfg:           config.GetAppConfig(),
	}
}

func (h *IPReputationScorer) Handle(ctx *pipeline.Context) error {
	if ctx.HardDecision {
		return nil
	}

	if ctx.ShouldSkipModule("ip_reputation") {
		ctx.AddTrace(pipeline.StageTrace{Stage: "ip_reputation", Result: "SKIP"})
		return nil
	}

	cfg := h.getScoringConfig()
	if cfg != nil && !cfg.Weights.IPReputation.Enabled {
		ctx.AddTrace(pipeline.StageTrace{Stage: "ip_reputation", Result: "DISABLED"})
		return nil
	}

	maxScore := 25
	if cfg != nil {
		maxScore = cfg.Weights.IPReputation.MaxScore
	}

	var score int
	var reasons []string
	manualOverride := false

	// Check manual IP entry first (override MaxMind)
	if ipScore, found := h.ipRepService.LookupIP(ctx.ClientIP); found {
		score = ipScore
		if score > maxScore {
			score = maxScore
		}
		reasons = append(reasons, "Manual IP entry")
		manualOverride = true
	}

	// Check manual ASN entry (override MaxMind)
	if !manualOverride {
		asn := uint(ctx.ASN)
		if asn > 0 {
			if asnScore, found := h.ipRepService.LookupASN(asn); found {
				score = asnScore
				if score > maxScore {
					score = maxScore
				}
				reasons = append(reasons, "Manual ASN entry: "+strconv.FormatUint(uint64(asn), 10))
				manualOverride = true
			}
		}
	}

	// Fallback to MaxMind auto-detect if no manual override
	if !manualOverride {
		repCfg, _ := h.ipRepService.GetConfig()

		if ctx.IsDatacenter {
			dcScore := repCfg.MaxmindDCScore
			if dcScore > maxScore {
				dcScore = maxScore
			}
			score += dcScore
			reasons = append(reasons, "Datacenter ASN")
		}

		if asnOrg := ctx.ASNOrg; asnOrg != "" {
			if isCloudProvider(asnOrg) {
				asnScore := repCfg.MaxmindASNScore
				remaining := maxScore - score
				if asnScore > remaining {
					asnScore = remaining
				}
				score += asnScore
				reasons = append(reasons, "Cloud Provider: "+asnOrg)
			}
		}
	}

	if score > maxScore {
		score = maxScore
	}

	if score > 0 {
		ctx.AddScore(pipeline.ScoreCategoryIPReputation, "ip_reputation", score)
		h.appCfg.LogDebug("[IP_REPUTATION] Contributed score=%d to risk scoring ip=%s", score, ctx.ClientIP)
		ctx.AddTrace(pipeline.StageTrace{
			Stage:  "ip_reputation",
			Score:  score,
			Reason: joinReasons(reasons),
		})
	} else {
		ctx.AddTrace(pipeline.StageTrace{Stage: "ip_reputation", Score: 0})
	}

	return nil
}

func isCloudProvider(org string) bool {
	providers := []string{"amazon", "aws", "google cloud", "microsoft azure", "digitalocean", "linode", "vultr", "ovh", "hetzner"}
	orgLower := toLower(org)
	for _, p := range providers {
		if contains(orgLower, p) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
