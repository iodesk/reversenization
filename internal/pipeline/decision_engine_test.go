package pipeline

import (
	"testing"

	"github.com/vibeswaf/waf/internal/model"
)

func scoringCfg(block, challenge int) func() *model.ScoringConfig {
	cfg := model.DefaultScoringConfig()
	cfg.Thresholds.Block = block
	cfg.Thresholds.Challenge = challenge
	return func() *model.ScoringConfig { return &cfg }
}

func TestDecisionEngineBlock(t *testing.T) {
	e := NewDecisionEngine(scoringCfg(80, 50))
	ctx := &Context{RiskScore: NewRiskScore()}
	ctx.RiskScore.Total = 85

	if err := e.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "block" {
		t.Fatalf("Action = %q, want block (score 85 >= 80)", ctx.Action)
	}
}

func TestDecisionEngineChallenge(t *testing.T) {
	e := NewDecisionEngine(scoringCfg(80, 50))
	ctx := &Context{RiskScore: NewRiskScore()}
	ctx.RiskScore.Total = 60

	if err := e.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "challenge" {
		t.Fatalf("Action = %q, want challenge (50 <= 60 < 80)", ctx.Action)
	}
}

func TestDecisionEngineAllow(t *testing.T) {
	e := NewDecisionEngine(scoringCfg(80, 50))
	ctx := &Context{RiskScore: NewRiskScore()}
	ctx.RiskScore.Total = 30

	if err := e.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "" {
		t.Fatalf("Action = %q, want empty (allow, score 30 < 50)", ctx.Action)
	}
}

func TestDecisionEngineBoundaries(t *testing.T) {
	e := NewDecisionEngine(scoringCfg(80, 50))
	cases := []struct {
		score int
		want  string
	}{
		{49, ""},          // just below challenge
		{50, "challenge"}, // exactly challenge
		{79, "challenge"}, // just below block
		{80, "block"},     // exactly block
	}
	for _, tc := range cases {
		ctx := &Context{RiskScore: NewRiskScore()}
		ctx.RiskScore.Total = tc.score
		if err := e.Handle(ctx); err != nil {
			t.Fatalf("Handle error: %v", err)
		}
		if ctx.Action != tc.want {
			t.Errorf("score %d → Action %q, want %q", tc.score, ctx.Action, tc.want)
		}
	}
}

func TestDecisionEngineRespectsHardDecision(t *testing.T) {
	e := NewDecisionEngine(scoringCfg(80, 50))
	ctx := &Context{RiskScore: NewRiskScore(), HardDecision: true, Action: "block"}
	ctx.RiskScore.Total = 10 // would be allow, but hard decision already made

	if err := e.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "block" {
		t.Fatalf("hard decision must be preserved, got %q", ctx.Action)
	}
}

func TestDecisionEngineKeepsPhase1Action(t *testing.T) {
	e := NewDecisionEngine(scoringCfg(80, 50))
	ctx := &Context{RiskScore: NewRiskScore(), Action: "challenge"}
	ctx.RiskScore.Total = 90 // would escalate, but phase1 challenge is preserved per engine contract

	if err := e.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "challenge" {
		t.Fatalf("existing challenge action must be kept, got %q", ctx.Action)
	}
}

func TestDecisionEngineNilConfig(t *testing.T) {
	e := NewDecisionEngine(func() *model.ScoringConfig { return nil })
	ctx := &Context{RiskScore: NewRiskScore()}
	ctx.RiskScore.Total = 90

	if err := e.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "" {
		t.Fatalf("nil config should not decide, got %q", ctx.Action)
	}
}
