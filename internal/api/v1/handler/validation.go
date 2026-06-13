package handler

import (
	"fmt"

	"github.com/vibeswaf/waf/internal/model"
)


func ValidateBotConfig(config model.BotConfig) error {

	if config.Threshold < 0 || config.Threshold > 100 {
		return fmt.Errorf("invalid threshold: %d. Allowed range: 0-100", config.Threshold)
	}


	validActions := map[string]bool{"allow": true, "block": true, "challenge": true}
	if !validActions[config.Action] {
		return fmt.Errorf("invalid action: '%s'. Allowed values: 'allow', 'block', 'challenge'", config.Action)
	}


	if config.ChallengeDuration < 60 {
		return fmt.Errorf("invalid challenge_duration: %d seconds. Minimum allowed: 60 seconds (1 minute)", config.ChallengeDuration)
	}


	if config.ChallengeWait < 1 || config.ChallengeWait > 30 {
		return fmt.Errorf("invalid challenge_wait: %d seconds. Allowed range: 1-30 seconds", config.ChallengeWait)
	}


	for ruleName, score := range config.Rules {
		if score < 0 || score > 50 {
			return fmt.Errorf("invalid score for rule '%s': %d. Allowed range: 0-50", ruleName, score)
		}
	}

	return nil
}


func ValidateWAFConfig(config model.WAFConfig) error {

	if config.ParanoiaLevel < 1 || config.ParanoiaLevel > 4 {
		return fmt.Errorf("invalid paranoia_level: %d. Allowed range: 1-4", config.ParanoiaLevel)
	}

	if config.AnomalyThreshold < 1 || config.AnomalyThreshold > 100 {
		return fmt.Errorf("invalid anomaly_threshold: %d. Allowed range: 1-100", config.AnomalyThreshold)
	}

	return nil
}

func ValidateScoringConfig(config model.ScoringConfig) error {
	t := config.Thresholds

	if t.Block < 1 || t.Block > 100 {
		return fmt.Errorf("invalid block threshold: %d. Allowed range: 1-100", t.Block)
	}
	if t.Challenge < 1 || t.Challenge > 100 {
		return fmt.Errorf("invalid challenge threshold: %d. Allowed range: 1-100", t.Challenge)
	}

	if t.Block <= t.Challenge {
		return fmt.Errorf("block threshold (%d) must be greater than challenge threshold (%d)", t.Block, t.Challenge)
	}

	validateWeight := func(name string, w model.CategoryWeight) error {
		if w.MaxScore < 0 || w.MaxScore > 100 {
			return fmt.Errorf("invalid max_score for %s: %d. Allowed range: 0-100", name, w.MaxScore)
		}
		if w.Multiplier < 0 || w.Multiplier > 5.0 {
			return fmt.Errorf("invalid multiplier for %s: %.2f. Allowed range: 0-5.0", name, w.Multiplier)
		}
		return nil
	}

	if err := validateWeight("ip_reputation", config.Weights.IPReputation); err != nil {
		return err
	}
	if err := validateWeight("bot_detection", config.Weights.BotDetection); err != nil {
		return err
	}
	if err := validateWeight("waf_anomaly", config.Weights.WAFAnomaly); err != nil {
		return err
	}
	if err := validateWeight("protocol_anomaly", config.Weights.ProtocolAnomaly); err != nil {
		return err
	}

	return nil
}
