package logger

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vibeswaf/waf/internal/config"
)

func runCleanup(ctx context.Context, conn driver.Conn, retentionDays int, appCfg *config.AppConfig) {
	if conn == nil {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	query := fmt.Sprintf("ALTER TABLE waf_events DELETE WHERE ts < '%s'", cutoff.Format("2006-01-02 15:04:05"))
	if err := conn.Exec(ctx, query); err != nil {
		appCfg.LogError("[RetentionWorker] cleanup error: %v", err)
		return
	}
	appCfg.LogInfo("[RetentionWorker] cleanup done cutoff=%s", cutoff.Format(time.RFC3339))
}

func retentionLoop(ctx context.Context, conn driver.Conn, retentionDays int, intervalHours int, appCfg *config.AppConfig) {
	ticker := time.NewTicker(time.Duration(intervalHours) * time.Hour)
	defer ticker.Stop()
	defer func() {
		if r := recover(); r != nil {
			appCfg.LogError("[RetentionWorker] recovered from panic: %v", r)
		}
	}()
	for {
		select {
		case <-ticker.C:
			runCleanup(ctx, conn, retentionDays, appCfg)
		case <-ctx.Done():
			appCfg.LogStartup("[RetentionWorker] stopped")
			return
		}
	}
}

func (c *Clickhouse) StartRetentionWorker(ctx context.Context, appCfg *config.AppConfig) {
	appCfg.LogStartup("[RetentionWorker] started retention_days=%d interval_hours=%d", appCfg.RetentionDays, appCfg.RetentionIntervalHours)
	go retentionLoop(ctx, c.conn, appCfg.RetentionDays, appCfg.RetentionIntervalHours, appCfg)
}
