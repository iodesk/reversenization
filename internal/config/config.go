package config

import (
	"time"

	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/store"
)

type Manager struct {
	pg    *Postgres
	cache *store.Memory
	ttl   time.Duration
}

func NewManager(pg *Postgres, cacheTTL time.Duration) *Manager {
	return &Manager{
		pg:    pg,
		cache: store.NewMemory(),
		ttl:   cacheTTL,
	}
}

func (m *Manager) Get(domain string) (*model.AppConfig, error) {

	if cached, ok := m.cache.Get("config:" + domain); ok {
		return cached.(*model.AppConfig), nil
	}


	config, err := m.pg.GetAppConfig(domain)
	if err != nil {
		return nil, err
	}


	m.cache.Set("config:"+domain, config, m.ttl)

	return config, nil
}

func (m *Manager) Invalidate(domain string) {
	m.cache.Del("config:" + domain)
}
