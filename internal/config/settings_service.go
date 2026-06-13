package config

import "github.com/vibeswaf/waf/internal/model"

type SettingsReader interface {
	GetWAFConfig() (model.WAFConfig, error)
	GetBotConfig() (model.BotConfig, error)
	GetRateLimitConfig() (model.RateLimitConfig, error)
}

type SettingsService struct {
	repo SettingsReader
}

func NewSettingsService(repo SettingsReader) *SettingsService {
	return &SettingsService{repo: repo}
}

func (s *SettingsService) GetWAFConfig() (model.WAFConfig, error) {
	return s.repo.GetWAFConfig()
}

func (s *SettingsService) GetBotConfig() (model.BotConfig, error) {
	return s.repo.GetBotConfig()
}

func (s *SettingsService) GetRateLimitConfig() (model.RateLimitConfig, error) {
	return s.repo.GetRateLimitConfig()
}
