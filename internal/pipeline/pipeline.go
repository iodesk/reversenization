package pipeline

import (
	"errors"
	"fmt"
	"time"

	"github.com/vibeswaf/waf/internal/model"
)

var ErrResponseWritten = errors.New("response already written")

type Handler interface {
	Handle(ctx *Context) error
}

type HandlerFunc func(ctx *Context) error

func (f HandlerFunc) Handle(ctx *Context) error {
	return f(ctx)
}

type PipelineError struct {
	Action string
	Reason string
	Stage  string
}

func (e *PipelineError) Error() string {
	return fmt.Sprintf("pipeline stopped: action=%s stage=%s reason=%s", e.Action, e.Stage, e.Reason)
}

func NewPipelineError(action, stage, reason string) *PipelineError {
	return &PipelineError{Action: action, Stage: stage, Reason: reason}
}

type Pipeline struct {
	phase1        []Handler
	phase2        []Handler
	phase3        Handler
	phase4        []Handler
	scoringConfig *model.ScoringConfig
	getScoringConfig func() *model.ScoringConfig
}

type PipelineConfig struct {
	Phase1        []Handler
	Phase2        []Handler
	Phase3        Handler
	Phase4        []Handler
	ScoringConfig *model.ScoringConfig
	GetScoringConfig func() *model.ScoringConfig
}

func New(cfg PipelineConfig) *Pipeline {
	return &Pipeline{
		phase1:           cfg.Phase1,
		phase2:           cfg.Phase2,
		phase3:           cfg.Phase3,
		phase4:           cfg.Phase4,
		scoringConfig:    cfg.ScoringConfig,
		getScoringConfig: cfg.GetScoringConfig,
	}
}

func (p *Pipeline) SetScoringConfig(cfg *model.ScoringConfig) {
	p.scoringConfig = cfg
}

func (p *Pipeline) GetScoringConfig() *model.ScoringConfig {
	return p.scoringConfig
}

func (p *Pipeline) Execute(ctx *Context) error {
	ctx.Normalized = Normalize(ctx)
	ctx.RiskScore = NewRiskScore()
	ctx.Trace = NewPipelineTrace()
	start := time.Now()

	// Phase 1: Deterministic hard rules — early exit on block/challenge
	for _, h := range p.phase1 {
		if err := h.Handle(ctx); err != nil {
			ctx.Trace.Phase = "HARD_RULE"
			ctx.Trace.Decision = ctx.Action
			ctx.PipelineDurationUS = time.Since(start).Microseconds()
			return err
		}
	}

	// If Phase 1 made a hard decision, skip scoring
	if ctx.HardDecision {
		ctx.PhaseExit = "phase1"
		ctx.Trace.Phase = "HARD_RULE"
		ctx.Trace.Decision = ctx.Action
		for _, h := range p.phase4 {
			if err := h.Handle(ctx); err != nil {
				ctx.PipelineDurationUS = time.Since(start).Microseconds()
				return err
			}
		}
		ctx.PipelineDurationUS = time.Since(start).Microseconds()
		return nil
	}

	// Phase 2: Adaptive scoring — all handlers contribute score
	for _, h := range p.phase2 {
		if err := h.Handle(ctx); err != nil {
			ctx.PipelineDurationUS = time.Since(start).Microseconds()
			return err
		}
	}

	// Apply caps and multipliers from scoring config (use fresh config)
	if p.getScoringConfig != nil {
		if freshCfg := p.getScoringConfig(); freshCfg != nil {
			p.applyWeightsWithConfig(ctx, freshCfg)
			p.enrichTraceWithWeights(ctx, freshCfg)
		}
	} else if p.scoringConfig != nil {
		p.applyWeights(ctx)
		p.enrichTraceWithWeights(ctx, p.scoringConfig)
	}
	ctx.RiskScore.ClampTotal()

	// Phase 3: Decision engine — evaluate total score
	if err := p.phase3.Handle(ctx); err != nil {
		ctx.PipelineDurationUS = time.Since(start).Microseconds()
		return err
	}

	// Finalize trace for scoring path
	ctx.Trace.Phase = "SCORING"
	decision := ctx.Action
	if decision == "" {
		decision = "allow"
	}
	ctx.Trace.Decision = decision
	ctx.Trace.Score = ctx.RiskScore.Total

	// Phase 4: Response handlers (block page, challenge page)
	for _, h := range p.phase4 {
		if err := h.Handle(ctx); err != nil {
			ctx.PipelineDurationUS = time.Since(start).Microseconds()
			return err
		}
	}

	ctx.PipelineDurationUS = time.Since(start).Microseconds()
	return nil
}

// ExecuteWebSocketChecks runs Phase 1 partial checks (IP access, flood, rate limit)
// without WAF body scanning or scoring. Used for WebSocket upgrade requests.
func (p *Pipeline) ExecuteWebSocketChecks(ctx *Context) {
	ctx.Normalized = Normalize(ctx)
	ctx.RiskScore = NewRiskScore()
	ctx.Trace = NewPipelineTrace()

	// Run only Phase 1 handlers (IP rules, challenge validator, flood, rate limit)
	// These are network-level checks that don't need request body.
	for _, h := range p.phase1 {
		if err := h.Handle(ctx); err != nil {
			return
		}
		// Stop if a hard decision was made (block/challenge)
		if ctx.HardDecision {
			return
		}
	}
}

func (p *Pipeline) applyWeights(ctx *Context) {
	cfg := p.scoringConfig
	if cfg == nil {
		return
	}
	p.applyWeightsWithConfig(ctx, cfg)
}

func (p *Pipeline) applyWeightsWithConfig(ctx *Context, cfg *model.ScoringConfig) {
	rs := ctx.RiskScore

	applyCategory := func(cat ScoreCategory, cw model.CategoryWeight) {
		if !cw.Enabled {
			if score, ok := rs.ByCategory[cat]; ok && score > 0 {
				rs.Total -= score
				rs.ByCategory[cat] = 0
			}
			return
		}
		rs.ApplyMultiplier(cat, cw.Multiplier)
		rs.ApplyCap(cat, cw.MaxScore)
	}

	applyCategory(ScoreCategoryIPReputation, cfg.Weights.IPReputation)
	applyCategory(ScoreCategoryBotDetection, cfg.Weights.BotDetection)
	applyCategory(ScoreCategoryWAFAnomaly, cfg.Weights.WAFAnomaly)
	applyCategory(ScoreCategoryProtocolAnomaly, cfg.Weights.ProtocolAnomaly)
}

func (p *Pipeline) enrichTraceWithWeights(ctx *Context, cfg *model.ScoringConfig) {
	if ctx.Trace == nil || ctx.RiskScore == nil {
		return
	}

	categoryWeights := map[string]model.CategoryWeight{
		"ip_reputation":    cfg.Weights.IPReputation,
		"bot_detection":    cfg.Weights.BotDetection,
		"waf_anomaly":      cfg.Weights.WAFAnomaly,
		"protocol_anomaly": cfg.Weights.ProtocolAnomaly,
	}

	categoryFinal := map[string]int{
		"ip_reputation":    ctx.RiskScore.ByCategory[ScoreCategoryIPReputation],
		"bot_detection":    ctx.RiskScore.ByCategory[ScoreCategoryBotDetection],
		"waf_anomaly":      ctx.RiskScore.ByCategory[ScoreCategoryWAFAnomaly],
		"protocol_anomaly": ctx.RiskScore.ByCategory[ScoreCategoryProtocolAnomaly],
	}

	for i := range ctx.Trace.Stages {
		stage := &ctx.Trace.Stages[i]
		if stage.Score == 0 {
			continue
		}
		cw, ok := categoryWeights[stage.Stage]
		if !ok {
			continue
		}
		if !cw.Enabled {
			stage.FinalScore = 0
			stage.Multiplier = 0
			continue
		}
		stage.Multiplier = cw.Multiplier
		stage.FinalScore = categoryFinal[stage.Stage]
	}
}
