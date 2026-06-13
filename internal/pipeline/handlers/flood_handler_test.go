package handlers

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/ratelimit"
)

func newFloodTestContext() *pipeline.Context {
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	return &pipeline.Context{
		Request:  req,
		Writer:   httptest.NewRecorder(),
		ClientIP: "1.2.3.4",
	}
}

// A terminal IP access rule (e.g. allowlist) must bypass flood entirely, even
// when the IP currently carries a flood challenge penalty.
func TestFloodSkippedWhenIPRuleTerminal(t *testing.T) {
	fp := ratelimit.NewFloodProtector(1, 1, 1, time.Minute, time.Minute, time.Minute)
	defer fp.Stop()

	// Put the IP under an active flood penalty.
	fp.SetChallenge("1.2.3.4", time.Minute)

	h := NewFloodHandler(fp, nil)

	ctx := newFloodTestContext()
	ctx.IPRuleTerminal = true

	if err := h.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action == "challenge" {
		t.Fatal("flood must be skipped for terminal IP rule, but it challenged")
	}
	if ctx.HardDecision {
		t.Fatal("flood must not set HardDecision when IP rule is terminal")
	}
}

func TestFloodSkippedWhenChallengePassed(t *testing.T) {
	fp := ratelimit.NewFloodProtector(1, 1, 1, time.Minute, time.Minute, time.Minute)
	defer fp.Stop()
	fp.SetChallenge("1.2.3.4", time.Minute)

	h := NewFloodHandler(fp, nil)

	ctx := newFloodTestContext()
	ctx.ChallengePassed = true

	if err := h.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action == "challenge" {
		t.Fatal("flood must be skipped when challenge already passed")
	}
}

func TestFloodChallengesPenalizedIP(t *testing.T) {
	fp := ratelimit.NewFloodProtector(1, 1, 1, time.Minute, time.Minute, time.Minute)
	defer fp.Stop()
	fp.SetChallenge("1.2.3.4", time.Minute)

	h := NewFloodHandler(fp, nil)

	ctx := newFloodTestContext() // no terminal rule, no challenge passed

	if err := h.Handle(ctx); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	if ctx.Action != "challenge" {
		t.Fatalf("penalized IP should be challenged, got %q", ctx.Action)
	}
	if !ctx.HardDecision {
		t.Fatal("flood challenge should set HardDecision")
	}
}
