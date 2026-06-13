package pipeline

import (
	"net/http/httptest"
	"testing"

	"github.com/vibeswaf/waf/internal/model"
)

// stubHandler runs an arbitrary function, used to simulate pipeline stages.
type stubHandler struct {
	fn func(ctx *Context) error
}

func (s stubHandler) Handle(ctx *Context) error { return s.fn(ctx) }

func newTestContext() *Context {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Host = "example.com"
	return &Context{
		Request:  req,
		Writer:   httptest.NewRecorder(),
		ClientIP: "1.2.3.4",
	}
}

func defaultScoringGetter() func() *model.ScoringConfig {
	cfg := model.DefaultScoringConfig()
	return func() *model.ScoringConfig { return &cfg }
}

func TestPipelineScoringPathAllow(t *testing.T) {
	getCfg := defaultScoringGetter()
	p := New(PipelineConfig{
		Phase2: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.AddScore(ScoreCategoryWAFAnomaly, "minor", 10)
				return nil
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	if err := p.Execute(ctx); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if ctx.Action != "" {
		t.Fatalf("Action = %q, want empty (allow, total 10)", ctx.Action)
	}
	if ctx.RiskScore.Total != 10 {
		t.Fatalf("risk total = %d, want 10", ctx.RiskScore.Total)
	}
	if ctx.Trace.Phase != "SCORING" {
		t.Fatalf("trace phase = %q, want SCORING", ctx.Trace.Phase)
	}
}

func TestPipelineScoringPathBlock(t *testing.T) {
	getCfg := defaultScoringGetter()
	p := New(PipelineConfig{
		Phase2: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.AddScore(ScoreCategoryWAFAnomaly, "sqli", 40)
				ctx.AddScore(ScoreCategoryIPReputation, "dc", 25)
				ctx.AddScore(ScoreCategoryBotDetection, "bot", 20)
				return nil
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	if err := p.Execute(ctx); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if ctx.Action != "block" {
		t.Fatalf("Action = %q, want block (total 85 >= 80)", ctx.Action)
	}
}

func TestPipelinePhase1EarlyExitSkipsScoring(t *testing.T) {
	getCfg := defaultScoringGetter()
	scored := false
	p := New(PipelineConfig{
		Phase1: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.AddDecision(NewDecision("block", "ip_rule", "blacklist"))
				ctx.HardDecision = true
				return nil
			}},
		},
		Phase2: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				scored = true
				ctx.AddScore(ScoreCategoryWAFAnomaly, "x", 5)
				return nil
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	if err := p.Execute(ctx); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if scored {
		t.Fatal("Phase 2 scoring must be skipped after a hard decision")
	}
	if ctx.Action != "block" {
		t.Fatalf("Action = %q, want block", ctx.Action)
	}
	if ctx.PhaseExit != "phase1" {
		t.Fatalf("PhaseExit = %v, want phase1", ctx.PhaseExit)
	}
	if ctx.Trace.Phase != "HARD_RULE" {
		t.Fatalf("trace phase = %q, want HARD_RULE", ctx.Trace.Phase)
	}
}

func TestPipelinePhase1ErrorPropagates(t *testing.T) {
	getCfg := defaultScoringGetter()
	sentinel := NewPipelineError("block", "flood", "attack")
	p := New(PipelineConfig{
		Phase1: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.Action = "block"
				return sentinel
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	err := p.Execute(ctx)
	if err != sentinel {
		t.Fatalf("Execute err = %v, want sentinel", err)
	}
	if ctx.Action != "block" {
		t.Fatalf("Action = %q, want block (set before error)", ctx.Action)
	}
}

func TestPipelineDisabledCategoryRemovedFromScore(t *testing.T) {
	cfg := model.DefaultScoringConfig()
	cfg.Weights.IPReputation.Enabled = false // disable IP reputation
	getCfg := func() *model.ScoringConfig { return &cfg }

	p := New(PipelineConfig{
		Phase2: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.AddScore(ScoreCategoryIPReputation, "dc", 25)
				ctx.AddScore(ScoreCategoryWAFAnomaly, "sqli", 30)
				return nil
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	if err := p.Execute(ctx); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	// IP reputation (25) removed, only WAF (30) remains.
	if ctx.RiskScore.Total != 30 {
		t.Fatalf("risk total = %d, want 30 (IP reputation disabled)", ctx.RiskScore.Total)
	}
	if ctx.RiskScore.ByCategory[ScoreCategoryIPReputation] != 0 {
		t.Fatalf("disabled category should be zeroed, got %d", ctx.RiskScore.ByCategory[ScoreCategoryIPReputation])
	}
}

func TestPipelineCategoryCapApplied(t *testing.T) {
	cfg := model.DefaultScoringConfig()
	cfg.Weights.WAFAnomaly.MaxScore = 40
	getCfg := func() *model.ScoringConfig { return &cfg }

	p := New(PipelineConfig{
		Phase2: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.AddScore(ScoreCategoryWAFAnomaly, "many", 70) // over the 40 cap
				return nil
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	if err := p.Execute(ctx); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if ctx.RiskScore.Total != 40 {
		t.Fatalf("risk total = %d, want 40 (capped)", ctx.RiskScore.Total)
	}
}

func TestPipelineMultiplierApplied(t *testing.T) {
	cfg := model.DefaultScoringConfig()
	cfg.Weights.BotDetection.Multiplier = 2.0
	cfg.Weights.BotDetection.MaxScore = 100
	getCfg := func() *model.ScoringConfig { return &cfg }

	p := New(PipelineConfig{
		Phase2: []Handler{
			stubHandler{fn: func(ctx *Context) error {
				ctx.AddScore(ScoreCategoryBotDetection, "bot", 20)
				return nil
			}},
		},
		Phase3:           NewDecisionEngine(getCfg),
		GetScoringConfig: getCfg,
	})

	ctx := newTestContext()
	if err := p.Execute(ctx); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if ctx.RiskScore.Total != 40 {
		t.Fatalf("risk total = %d, want 40 (20 * 2.0)", ctx.RiskScore.Total)
	}
}
