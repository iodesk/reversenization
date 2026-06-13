package config

import "github.com/vibeswaf/waf/internal/model"

type WAFConfigReader interface {
	GetWAFConfig() (model.WAFConfig, error)
}

type WAFConfigLoader struct {
	repo WAFConfigReader
}

func NewWAFConfigLoader(repo WAFConfigReader) *WAFConfigLoader {
	return &WAFConfigLoader{repo: repo}
}

func (l *WAFConfigLoader) Load() (model.WAFConfig, error) {
	cfg, err := l.repo.GetWAFConfig()
	if err != nil {
		return model.DefaultWAFConfig(), err
	}
	return cfg, nil
}
