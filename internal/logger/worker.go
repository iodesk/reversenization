package logger

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/vibeswaf/waf/internal/config"
)

func (c *Clickhouse) worker() {
	batch := make([]LogEntry, 0, 1000)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			// Drain remaining entries before exit
			for {
				select {
				case entry := <-c.ch:
					batch = append(batch, entry)
				default:
					if len(batch) > 0 {
						c.flush(batch)
					}
					return
				}
			}

		case entry := <-c.ch:
			batch = append(batch, entry)
			if len(batch) >= 1000 {
				c.flush(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				c.flush(batch)
				batch = batch[:0]
			}
		}
	}
}

func (c *Clickhouse) flush(batch []LogEntry) {
	if c.conn == nil {
		return
	}

	appCfg := config.GetAppConfig()
	appCfg.LogDebug("[ClickHouse] Flushing batch of %d entries", len(batch))

	ctx := context.Background()
	b, err := c.conn.PrepareBatch(ctx, `INSERT INTO waf_events (
		ts, ip, host, path, ua, action, reason, status,
		latency, pipeline_latency, upstream_latency,
		app_id, country, asn, asn_org, device_type, os, cache_hit, pipeline_trace
	)`)
	if err != nil {
		appCfg.LogError("[ClickHouse] prepare batch error: %v", err)
		return
	}

	for _, entry := range batch {
		err = b.Append(
			entry.TS,
			entry.IP,
			entry.Host,
			entry.Path,
			entry.UA,
			entry.Action,
			entry.Reason,
			entry.Status,
			entry.Latency,
			entry.PipelineLatency,
			entry.UpstreamLatency,
			entry.AppID,
			entry.Country,
			entry.ASN,
			entry.ASNOrg,
			entry.DeviceType,
			entry.OS,
			entry.CacheHit,
			entry.PipelineTrace,
		)
		if err != nil {
			appCfg.LogError("[ClickHouse] append error: %v", err)
			continue
		}
	}

	if err := b.Send(); err != nil {
		appCfg.LogError("[ClickHouse] send batch error: %v", err)
	} else {
		appCfg.LogDebug("[ClickHouse] Successfully flushed %d entries", len(batch))
	}
}

func (c *Clickhouse) Connect(host, database, user, password string) error {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{host},
		Auth: clickhouse.Auth{
			Database: database,
			Username: user,
			Password: password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout:     5 * time.Second,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 10 * time.Minute,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	})

	if err != nil {
		return fmt.Errorf("clickhouse connect error: %w", err)
	}

	if err := conn.Ping(context.Background()); err != nil {
		return fmt.Errorf("clickhouse ping error: %w", err)
	}

	c.conn = conn
	appCfg := config.GetAppConfig()
	appCfg.LogInfo("[ClickHouse] Connected successfully")
	return nil
}

func (c *Clickhouse) Close() error {
	close(c.stopCh)
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
