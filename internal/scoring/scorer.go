package scoring

import (
	"strings"

	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
)

type Scorer struct {
	Config model.BotConfig
}

func NewScorer() *Scorer {
	return &Scorer{Config: model.DefaultBotConfig()}
}

func NewScorerWithConfig(config model.BotConfig) *Scorer {
	return &Scorer{Config: config}
}

func (s *Scorer) AnalyzeHeaders(ctx *pipeline.Context) *model.BotScore {
	score := &model.BotScore{}

	ua := ctx.Request.UserAgent()
	accept := ctx.Request.Header.Get("Accept")
	acceptEncoding := ctx.Request.Header.Get("Accept-Encoding")
	acceptLanguage := ctx.Request.Header.Get("Accept-Language")
	secFetchSite := ctx.Request.Header.Get("Sec-Fetch-Site")
	secFetchMode := ctx.Request.Header.Get("Sec-Fetch-Mode")
	secFetchDest := ctx.Request.Header.Get("Sec-Fetch-Dest")
	secChUA := ctx.Request.Header.Get("Sec-CH-UA")

	// --- User-Agent checks ---
	if ua == "" {
		score.Add("missing_user_agent", s.Config.Rules["missing_user_agent"])
	} else if len(ua) < 20 {
		score.Add("short_user_agent", s.Config.Rules["short_user_agent"])
	}

	// --- Accept checks ---
	if accept == "" {
		score.Add("missing_accept", s.Config.Rules["missing_accept"])
	} else if accept == "*/*" && looksLikeBrowserUA(ua) {
		score.Add("wildcard_accept_browser_ua", s.Config.Rules["wildcard_accept_browser_ua"])
	}

	// --- Accept-Language ---
	if acceptLanguage == "" {
		score.Add("missing_accept_language", s.Config.Rules["missing_accept_language"])
	}

	// --- Accept-Encoding: missing entirely, or present but no gzip/br ---
	if acceptEncoding == "" {
		score.Add("missing_accept_encoding", s.Config.Rules["missing_accept_encoding"])
	} else if !strings.Contains(acceptEncoding, "gzip") && !strings.Contains(acceptEncoding, "br") {
		score.Add("no_gzip_or_br", s.Config.Rules["no_gzip_or_br"])
	}

	// --- Sec-Fetch completeness ---
	hasSite := secFetchSite != ""
	hasMode := secFetchMode != ""
	hasDest := secFetchDest != ""
	hasAny := hasSite || hasMode || hasDest
	hasAll := hasSite && hasMode && hasDest

	if !hasAny && looksLikeBrowserUA(ua) {
		score.Add("missing_sec_fetch", s.Config.Rules["missing_sec_fetch"])
	} else if hasAny && !hasAll {
		score.Add("incomplete_sec_fetch", s.Config.Rules["incomplete_sec_fetch"])
	}

	// --- Browser consistency: Chromium ---
	if looksLikeChromiumUA(ua) {
		if secChUA == "" {
			score.Add("chromium_missing_sec_ch_ua", s.Config.Rules["chromium_missing_sec_ch_ua"])
		}
		if !hasAny {
			score.Add("chromium_missing_sec_fetch", s.Config.Rules["chromium_missing_sec_fetch"])
		}
	}

	// --- Browser consistency: Firefox ---
	if looksLikeFirefoxUA(ua) && secChUA != "" {
		score.Add("firefox_has_sec_ch_ua", s.Config.Rules["firefox_has_sec_ch_ua"])
	}

	// --- No browser indicators: no Referer, no X-Requested-With, wildcard Accept ---
	if ctx.Request.Header.Get("X-Requested-With") == "" &&
		ctx.Request.Header.Get("Referer") == "" &&
		accept == "*/*" {
		score.Add("no_browser_indicators", s.Config.Rules["no_browser_indicators"])
	}

	// --- Headless/automation browser detection ---
	if isHeadlessUA(ua) {
		score.Add("headless_browser", s.Config.Rules["headless_browser"])
	}

	// --- Behavioral signals from typed fields (set by analyzeBehavior) ---
	if ctx.GeoLangMismatch {
		score.Add("geo_lang_mismatch", s.Config.Rules["geo_lang_mismatch"])
	}
	if ctx.RepeatNoCookie {
		score.Add("repeat_no_cookie", s.Config.Rules["repeat_no_cookie"])
	}
	if ctx.BurstRate {
		score.Add("burst_rate", s.Config.Rules["burst_rate"])
	}
	if ctx.RegularInterval {
		score.Add("regular_interval", s.Config.Rules["regular_interval"])
	}
	if ctx.UnknownBrowserBot {
		score.Add("unknown_browser_bot", s.Config.Rules["unknown_browser_bot"])
	}

	return score
}

func (s *Scorer) AnalyzeUserAgent(ua string, patterns []model.BotPattern) *model.BotScore {
	score := &model.BotScore{}
	if ua == "" {
		return score
	}

	uaLower := strings.ToLower(ua)
	matchedBadBot := false
	matchedSuspicious := false

	for _, pattern := range patterns {
		if !pattern.Enabled {
			continue
		}
		patternLower := pattern.PatternLower
		if patternLower == "" {
			patternLower = strings.ToLower(pattern.Pattern)
		}
		if !strings.Contains(uaLower, patternLower) {
			continue
		}
		switch pattern.PatternType {
		case "good_bot":
			if score.Metadata == nil {
				score.Metadata = make(map[string]interface{})
			}
			score.Metadata["potential_good_bot"] = pattern.Pattern
			score.Metadata["verify_ip"] = pattern.VerifyIP
			score.Metadata["pattern_score"] = pattern.Score
			score.Add("potential_good_bot:"+pattern.Pattern, 0)
		case "bad_bot":
			if !matchedBadBot {
				s := pattern.Score
				if s > 10 {
					s = 10
				}
				score.Add("bad_bot:"+pattern.Pattern, s)
				matchedBadBot = true
			}
		case "suspicious_ua":
			if !matchedSuspicious {
				s := pattern.Score
				if s > 5 {
					s = 5
				}
				score.Add("suspicious:"+pattern.Pattern, s)
				matchedSuspicious = true
			}
		}
	}

	return score
}

func (s *Scorer) AnalyzeReferer(referer string, patterns []model.BotPattern) *model.BotScore {
	score := &model.BotScore{}
	if referer == "" {
		return score
	}

	refererLower := strings.ToLower(referer)
	for _, pattern := range patterns {
		if !pattern.Enabled || pattern.PatternType != "bad_referer" {
			continue
		}
		patternLower := pattern.PatternLower
		if patternLower == "" {
			patternLower = strings.ToLower(pattern.Pattern)
		}
		if strings.Contains(refererLower, patternLower) {
			s := pattern.Score
			if s > 10 {
				s = 10
			}
			score.Add("bad_referer:"+pattern.Pattern, s)
		}
	}

	return score
}

func (s *Scorer) CombineScores(scores ...*model.BotScore) *model.BotScore {
	combined := &model.BotScore{}
	for _, sc := range scores {
		if sc == nil {
			continue
		}
		combined.TotalScore += sc.TotalScore
		combined.Reasons = append(combined.Reasons, sc.Reasons...)
		if sc.Metadata != nil && combined.Metadata == nil {
			combined.Metadata = sc.Metadata
		}
	}
	if combined.TotalScore > 100 {
		combined.TotalScore = 100
	}
	return combined
}

func (s *Scorer) DetermineAction(score int, threshold int, configAction string) string {
	if score < 0 {
		return "allow"
	}
	if score >= threshold {
		return configAction
	}
	return ""
}
