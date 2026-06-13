package cache

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vibeswaf/waf/internal/config"
)

var ErrCacheDisabled = errors.New("cache disabled")

type RedisClient struct {
	client  *redis.Client
	enabled bool
	mu      sync.RWMutex
	stopCh  chan struct{}
}

func NewDisabledClient() *RedisClient {
	return &RedisClient{enabled: false, stopCh: make(chan struct{})}
}

func NewRedisClient(addr, password string) *RedisClient {
	opts := &redis.Options{
		Password:     password,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		PoolSize:     100,
		MinIdleConns: 10,
	}

	if strings.HasPrefix(addr, "/") || strings.HasSuffix(addr, ".sock") {
		opts.Network = "unix"
		opts.Addr = addr
	} else {
		opts.Addr = addr
	}

	client := redis.NewClient(opts)

	rc := &RedisClient{
		client: client,
		stopCh: make(chan struct{}),
	}

	// Single ping attempt, reconnect loop handles retry
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err := client.Ping(ctx).Err()
	cancel()

	if err == nil {
		rc.mu.Lock()
		rc.enabled = true
		rc.mu.Unlock()
		config.GetAppConfig().LogStartup("Redis: ok")
	} else {
		config.GetAppConfig().LogWarn("[Redis] Unavailable at startup, will retry in background")
		go rc.reconnectLoop()
	}

	return rc
}

func (r *RedisClient) reconnectLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err := r.client.Ping(ctx).Err()
			cancel()

			if err == nil {
				r.mu.Lock()
				r.enabled = true
				r.mu.Unlock()
				config.GetAppConfig().LogInfo("[Redis] Reconnected successfully")
				return
			}
		}
	}
}

func (r *RedisClient) IsEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	r.mu.RLock()
	if !r.enabled {
		r.mu.RUnlock()
		return "", ErrCacheDisabled
	}
	r.mu.RUnlock()

	val, err := r.client.Get(ctx, key).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		r.checkHealth()
	}
	return val, err
}

func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	r.mu.RLock()
	if !r.enabled {
		r.mu.RUnlock()
		return ErrCacheDisabled
	}
	r.mu.RUnlock()

	err := r.client.Set(ctx, key, value, ttl).Err()
	if err != nil {
		r.checkHealth()
	}
	return err
}

func (r *RedisClient) Del(ctx context.Context, key string) error {
	r.mu.RLock()
	if !r.enabled {
		r.mu.RUnlock()
		return ErrCacheDisabled
	}
	r.mu.RUnlock()

	err := r.client.Del(ctx, key).Err()
	if err != nil {
		r.checkHealth()
	}
	return err
}

func (r *RedisClient) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	r.mu.RLock()
	if !r.enabled {
		r.mu.RUnlock()
		return 0, ErrCacheDisabled
	}
	r.mu.RUnlock()

	val, err := r.client.Incr(ctx, key).Result()
	if err != nil {
		r.checkHealth()
		return 0, err
	}
	if val == 1 {
		r.client.Expire(ctx, key, ttl)
	}
	return val, nil
}

func (r *RedisClient) GetInt(ctx context.Context, key string) (int64, error) {
	r.mu.RLock()
	if !r.enabled {
		r.mu.RUnlock()
		return 0, ErrCacheDisabled
	}
	r.mu.RUnlock()

	val, err := r.client.Get(ctx, key).Int64()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			r.checkHealth()
		}
		return 0, err
	}
	return val, nil
}

func (r *RedisClient) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := r.client.Ping(ctx).Err(); err != nil {
		r.mu.Lock()
		if r.enabled {
			r.enabled = false
			config.GetAppConfig().LogWarn("[Redis] Connection lost, disabling cache")
			go r.reconnectLoop()
		}
		r.mu.Unlock()
	}
}

func (r *RedisClient) Close() error {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}
