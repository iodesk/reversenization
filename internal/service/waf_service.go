package service

import (
	"fmt"

	"github.com/vibeswaf/waf/internal/logger"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/waf"
)

type WAFService struct {
	appService   *AppService
	settingsRepo *repository.SettingsRepository
	wafEngine    *waf.CorazaEngine
	logger       Logger
	appConfig    AppConfig
}

type AppConfig interface {
	IsDebug() bool
	LogDebug(format string, v ...interface{})
	LogInfo(format string, v ...interface{})
	LogWarn(format string, v ...interface{})
	LogError(format string, v ...interface{})
}

type Logger interface {
	Log(entry logger.LogEntry)
}

func NewWAFService(appService *AppService, settingsRepo *repository.SettingsRepository, logger Logger, appConfig AppConfig) *WAFService {
	cfg, err := settingsRepo.GetWAFConfig()
	if err != nil {
		appConfig.LogWarn("[WAF] Failed to load config from database, using defaults: %v", err)
		cfg = model.DefaultWAFConfig()
	}

	appConfig.LogInfo("[WAF] Initializing Coraza with PL=%d, Inbound Threshold=%d, Outbound Threshold=%d", cfg.ParanoiaLevel, cfg.AnomalyThreshold, cfg.OutboundAnomalyThreshold)

	corazaEngine, err := waf.NewCorazaEngine(cfg.ParanoiaLevel, cfg.AnomalyThreshold, cfg.OutboundAnomalyThreshold, cfg.AllowedMethods, cfg.DisabledRules, cfg.CustomRules, appConfig)
	if err != nil {
		appConfig.LogError("[WAF] Failed to initialize Coraza engine: %v", err)
		corazaEngine = nil
	} else {
		appConfig.LogInfo("[WAF] Coraza WAF engine initialized with OWASP CRS (PL%d)", cfg.ParanoiaLevel)
	}

	return &WAFService{
		appService:   appService,
		settingsRepo: settingsRepo,
		wafEngine:    corazaEngine,
		logger:       logger,
		appConfig:    appConfig,
	}
}

func (s *WAFService) ReloadWAFConfig(paranoiaLevel, anomalyThreshold, outboundAnomalyThreshold int, allowedMethods []string, disabledRules []int, customRules string) error {
	s.appConfig.LogInfo("[WAF] Reloading config: PL=%d, Inbound Threshold=%d, Outbound Threshold=%d", paranoiaLevel, anomalyThreshold, outboundAnomalyThreshold)

	next, err := waf.NewCorazaEngine(paranoiaLevel, anomalyThreshold, outboundAnomalyThreshold, allowedMethods, disabledRules, customRules, s.appConfig)
	if err != nil {
		return fmt.Errorf("failed to reinitialize WAF engine: %w", err)
	}

	old := s.wafEngine
	s.wafEngine = next

	if old != nil {
		_ = old.Close()
	}

	return nil
}

func (s *WAFService) Close() error {
	if s.wafEngine != nil {
		return s.wafEngine.Close()
	}
	return nil
}

// DetectOnly runs WAF detection and returns the WAF result
// without making any decision. Used by Phase 2 scoring pipeline.
func (s *WAFService) DetectOnly(ctx *pipeline.Context) *waf.WAFResult {
	if s.wafEngine == nil {
		return &waf.WAFResult{}
	}

	result, err := s.wafEngine.ProcessRequest(ctx.Request, ctx.ClientIP)
	if err != nil {
		s.appConfig.LogError("[WAF] DetectOnly error: %v", err)
		return &waf.WAFResult{}
	}

	s.appConfig.LogDebug("[WAF] DetectOnly result: score=%d, trigger=%s, matchedRules=%d", result.AnomalyScore, result.TriggerRule, len(result.MatchedRules))
	return result
}
