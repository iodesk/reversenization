package cache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
)

const (
	TTLBlock     = 60 * time.Second
	TTLChallenge = 30 * time.Second

	historySize     = 60
	historyInterval = 1 * time.Minute

	writeQueueSize = 4096
)

type CachedDecision struct {
	Action string `json:"action"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type cacheCounters struct {
	hits           int64
	misses         int64
	blockHits      int64
	challengeHits  int64
	totalLatencyUs int64
}

type HistoryPoint struct {
	Time          string  `json:"time"`
	HitRate       float64 `json:"hit_rate"`
	Hits          int64   `json:"hits"`
	Misses        int64   `json:"misses"`
	BlockHits     int64   `json:"block_hits"`
	ChallengeHits int64   `json:"challenge_hits"`
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
}

type CacheStats struct {
	Hits          int64          `json:"hits"`
	Misses        int64          `json:"misses"`
	HitRate       float64        `json:"hit_rate"`
	BlockHits     int64          `json:"block_hits"`
	ChallengeHits int64          `json:"challenge_hits"`
	AvgLatencyMs  float64        `json:"avg_latency_ms"`
	Enabled       bool           `json:"enabled"`
	History       []HistoryPoint `json:"history"`
}

// writeEntry is a pending cache write queued for the async writer.
type writeEntry struct {
	key  string
	data []byte
	ttl  time.Duration
}

type DecisionCache struct {
	redis  *RedisClient
	appCfg *config.AppConfig

	counters cacheCounters

	histMu   sync.RWMutex
	history  []HistoryPoint
	lastSnap cacheCounters

	// Async write channel — replaces per-request goroutine.
	writeCh chan writeEntry
	stopCh  chan struct{}
}

func NewDecisionCache(redis *RedisClient) *DecisionCache {
	dc := &DecisionCache{
		redis:   redis,
		appCfg:  config.GetAppConfig(),
		history: make([]HistoryPoint, 0, historySize),
		writeCh: make(chan writeEntry, writeQueueSize),
		stopCh:  make(chan struct{}),
	}
	go dc.historyWorker()
	go dc.writeWorker()
	return dc
}

// Stop terminates background goroutines.
func (c *DecisionCache) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

func (c *DecisionCache) historyWorker() {
	ticker := time.NewTicker(historyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.recordSnapshot()
		}
	}
}

// writeWorker drains the write channel and batches Redis writes.
// Single goroutine, no per-request spawn.
func (c *DecisionCache) writeWorker() {
	for {
		select {
		case <-c.stopCh:
			return
		case entry := <-c.writeCh:
			rctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			if err := c.redis.Set(rctx, entry.key, entry.data, entry.ttl); err != nil && !errors.Is(err, ErrCacheDisabled) {
				c.appCfg.LogDebug("[CACHE] Write failed key=%s: %v", entry.key, err)
			}
			cancel()
		}
	}
}

func (c *DecisionCache) recordSnapshot() {
	hits := atomic.LoadInt64(&c.counters.hits)
	misses := atomic.LoadInt64(&c.counters.misses)
	blockHits := atomic.LoadInt64(&c.counters.blockHits)
	challengeHits := atomic.LoadInt64(&c.counters.challengeHits)
	totalLatUs := atomic.LoadInt64(&c.counters.totalLatencyUs)

	c.histMu.Lock()
	defer c.histMu.Unlock()

	dHits := hits - c.lastSnap.hits
	dMisses := misses - c.lastSnap.misses
	dBlock := blockHits - c.lastSnap.blockHits
	dChallenge := challengeHits - c.lastSnap.challengeHits
	dLatUs := totalLatUs - c.lastSnap.totalLatencyUs

	c.lastSnap.hits = hits
	c.lastSnap.misses = misses
	c.lastSnap.blockHits = blockHits
	c.lastSnap.challengeHits = challengeHits
	c.lastSnap.totalLatencyUs = totalLatUs

	dTotal := dHits + dMisses
	var hitRate float64
	if dTotal > 0 {
		hitRate = float64(dHits) / float64(dTotal) * 100
	}

	var avgLatMs float64
	if dHits > 0 {
		avgLatMs = float64(dLatUs) / float64(dHits) / 1000.0
	}

	point := HistoryPoint{
		Time:          time.Now().Format("15:04"),
		HitRate:       hitRate,
		Hits:          dHits,
		Misses:        dMisses,
		BlockHits:     dBlock,
		ChallengeHits: dChallenge,
		AvgLatencyMs:  avgLatMs,
	}

	if len(c.history) >= historySize {
		c.history = c.history[1:]
	}
	c.history = append(c.history, point)
}

func (c *DecisionCache) Get(ctx *pipeline.Context) *CachedDecision {
	if !c.redis.IsEnabled() {
		return nil
	}

	key := c.generateKey(ctx)

	rctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	start := time.Now()
	val, err := c.redis.Get(rctx, key)
	latencyUs := time.Since(start).Microseconds()

	if err != nil {
		if !errors.Is(err, redis.Nil) && !errors.Is(err, ErrCacheDisabled) {
			c.appCfg.LogDebug("[CACHE] Get error key=%s: %v", key, err)
		}
		return nil
	}

	var decision CachedDecision
	if err := json.Unmarshal([]byte(val), &decision); err != nil {
		return nil
	}

	atomic.AddInt64(&c.counters.hits, 1)
	atomic.AddInt64(&c.counters.totalLatencyUs, latencyUs)
	switch decision.Action {
	case "block":
		atomic.AddInt64(&c.counters.blockHits, 1)
	case "challenge":
		atomic.AddInt64(&c.counters.challengeHits, 1)
	}

	c.appCfg.LogDebug("[CACHE] HIT key=%s action=%s latency=%dµs", key, decision.Action, latencyUs)
	return &decision
}

func (c *DecisionCache) Set(ctx *pipeline.Context, action, source, reason string) {
	if !c.redis.IsEnabled() {
		return
	}

	var ttl time.Duration
	switch action {
	case "block":
		ttl = TTLBlock
	case "challenge":
		ttl = TTLChallenge
	default:
		return
	}

	if !ctx.CacheHit {
		atomic.AddInt64(&c.counters.misses, 1)
	}

	key := c.generateKey(ctx)
	cached := CachedDecision{
		Action: action,
		Source: source,
		Reason: reason,
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return
	}

	// Non-blocking enqueue — drop if queue full (back-pressure safety).
	select {
	case c.writeCh <- writeEntry{key: key, data: data, ttl: ttl}:
	default:
	}
}

func (c *DecisionCache) GetStats() CacheStats {
	hits := atomic.LoadInt64(&c.counters.hits)
	misses := atomic.LoadInt64(&c.counters.misses)
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	var avgLatencyMs float64
	if hits > 0 {
		avgLatencyMs = float64(atomic.LoadInt64(&c.counters.totalLatencyUs)) / float64(hits) / 1000.0
	}

	c.histMu.RLock()
	history := make([]HistoryPoint, len(c.history))
	copy(history, c.history)
	c.histMu.RUnlock()

	return CacheStats{
		Hits:          hits,
		Misses:        misses,
		HitRate:       hitRate,
		BlockHits:     atomic.LoadInt64(&c.counters.blockHits),
		ChallengeHits: atomic.LoadInt64(&c.counters.challengeHits),
		AvgLatencyMs:  avgLatencyMs,
		Enabled:       c.redis.IsEnabled(),
		History:       history,
	}
}

func (c *DecisionCache) generateKey(ctx *pipeline.Context) string {
	h := sha256.New()

	if ctx.AppID != "" {
		h.Write([]byte(ctx.AppID))
	}
	h.Write([]byte(ctx.ClientIP))
	h.Write([]byte(ctx.Normalized.UA))
	h.Write([]byte(ctx.Normalized.Method))
	h.Write([]byte(ctx.Normalized.Path))
	h.Write([]byte(ctx.Normalized.Query))

	return fmt.Sprintf("waf:decision:%x", h.Sum(nil)[:12])
}
