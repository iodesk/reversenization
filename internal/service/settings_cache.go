package service

import (
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
)

// SettingsCache preloads the scoring config into memory and serves it via an
// atomic pointer read — zero DB query and zero lock on the request path.
// The scoring config is read ~5x per request (IP reputation, protocol anomaly,
// trust, decision engine, weight application), so caching it removes the single
// largest source of synchronous DB IO from the hot path.
//
// Refresh happens in the background on a fixed interval (DB → preload → memory →
// runtime, atomic swap), keeping dashboard-configurable values dynamic.
type SettingsCache struct {
	repo   *repository.SettingsRepository
	appCfg *config.AppConfig

	scoring unsafe.Pointer // *model.ScoringConfig

	reloadInterval time.Duration
	stopCh         chan struct{}
}

func NewSettingsCache(repo *repository.SettingsRepository) *SettingsCache {
	c := &SettingsCache{
		repo:           repo,
		appCfg:         config.GetAppConfig(),
		reloadInterval: 10 * time.Second,
		stopCh:         make(chan struct{}),
	}

	c.reload()
	go c.autoReload()
	return c
}

func (c *SettingsCache) reload() {
	scoring, err := c.repo.GetScoringConfig()
	if err != nil {
		c.appCfg.LogWarn("[SettingsCache] Failed to load scoring config: %v", err)
		if atomic.LoadPointer(&c.scoring) == nil {
			def := model.DefaultScoringConfig()
			atomic.StorePointer(&c.scoring, unsafe.Pointer(&def))
		}
		return
	}
	atomic.StorePointer(&c.scoring, unsafe.Pointer(&scoring))
}

func (c *SettingsCache) autoReload() {
	ticker := time.NewTicker(c.reloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.reload()
		}
	}
}

// GetScoringConfig returns the cached scoring config via an atomic read.
func (c *SettingsCache) GetScoringConfig() *model.ScoringConfig {
	return (*model.ScoringConfig)(atomic.LoadPointer(&c.scoring))
}

// Invalidate forces an immediate reload from the database.
// Call after a scoring-config write so changes propagate without waiting for the ticker.
func (c *SettingsCache) Invalidate() {
	c.reload()
}

// Stop terminates the background reload goroutine.
func (c *SettingsCache) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}
