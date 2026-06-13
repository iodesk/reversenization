package config

import (
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"

	"github.com/vibeswaf/waf/internal/model"
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Connection pool tuning for high concurrency. Defaults (MaxIdleConns=2,
	// MaxOpenConns=unlimited) lead to connection churn or exhaustion under load.
	db.SetMaxOpenConns(envInt("PSQL_MAX_OPEN_CONNS", 50))
	db.SetMaxIdleConns(envInt("PSQL_MAX_IDLE_CONNS", 25))
	db.SetConnMaxLifetime(time.Duration(envInt("PSQL_CONN_MAX_LIFETIME_MIN", 30)) * time.Minute)
	db.SetConnMaxIdleTime(time.Duration(envInt("PSQL_CONN_MAX_IDLE_MIN", 5)) * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &Postgres{db: db}, nil
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}


func (p *Postgres) GetAppConfig(domain string) (*model.AppConfig, error) {
	query := `
		SELECT 
			app_id, domain, config
		FROM applications 
		WHERE domain = $1
	`

	config := &model.AppConfig{}
	var configBytes []byte
	err := p.db.QueryRow(query, domain).Scan(
		&config.AppID, &config.Domain, &configBytes,
	)

	if err == sql.ErrNoRows {

		return &model.AppConfig{
			AppID:              "default",
			Domain:             domain,
			UseGlobalRateLimit: true,
			UseGlobalWAF:       true,
			UseGlobalBot:       true,
		}, nil
	}

	if err != nil {
		return nil, err
	}

	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

func (p *Postgres) Close() error {
	return p.db.Close()
}

func (p *Postgres) DB() *sql.DB {
	return p.db
}
