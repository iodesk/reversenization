package repository

import (
	"database/sql"
	"encoding/json"

	"github.com/vibeswaf/waf/internal/model"
)

type SettingsRepository struct {
	db *sql.DB
}

func NewSettingsRepository(db *sql.DB) *SettingsRepository {
	return &SettingsRepository{db: db}
}

func (r *SettingsRepository) GetBotConfig() (model.BotConfig, error) {
	var val []byte
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = 'bot_config'").Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.DefaultBotConfig(), nil
		}
		return model.BotConfig{}, err
	}

	var config model.BotConfig
	if err := json.Unmarshal(val, &config); err != nil {
		return model.BotConfig{}, err
	}

	return config, nil
}

func (r *SettingsRepository) UpdateBotConfig(config model.BotConfig) error {
	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('bot_config', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	return err
}

func (r *SettingsRepository) GetWAFConfig() (model.WAFConfig, error) {
	var val []byte
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = 'waf_config'").Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.DefaultWAFConfig(), nil
		}
		return model.WAFConfig{}, err
	}

	var config model.WAFConfig
	if err := json.Unmarshal(val, &config); err != nil {
		return model.WAFConfig{}, err
	}

	return config, nil
}

func (r *SettingsRepository) UpdateWAFConfig(config model.WAFConfig) error {
	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('waf_config', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	return err
}

func (r *SettingsRepository) GetRateLimitConfig() (model.RateLimitConfig, error) {
	var val []byte
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = 'rate_limit'").Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.DefaultRateLimitConfig(), nil
		}
		return model.RateLimitConfig{}, err
	}

	var config model.RateLimitConfig
	if err := json.Unmarshal(val, &config); err != nil {
		return model.RateLimitConfig{}, err
	}

	return config, nil
}

func (r *SettingsRepository) UpdateRateLimitConfig(config model.RateLimitConfig) error {
	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('rate_limit', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	return err
}

func (r *SettingsRepository) GetScoringConfig() (model.ScoringConfig, error) {
	var val []byte
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = 'scoring_config'").Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.DefaultScoringConfig(), nil
		}
		return model.ScoringConfig{}, err
	}

	var config model.ScoringConfig
	if err := json.Unmarshal(val, &config); err != nil {
		return model.ScoringConfig{}, err
	}

	return config, nil
}

func (r *SettingsRepository) UpdateScoringConfig(config model.ScoringConfig) error {
	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('scoring_config', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	return err
}

func (r *SettingsRepository) GetProtocolAnomalyConfig() (model.ProtocolAnomalyConfig, error) {
	var val []byte
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = 'protocol_anomaly_config'").Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.DefaultProtocolAnomalyConfig(), nil
		}
		return model.ProtocolAnomalyConfig{}, err
	}

	var config model.ProtocolAnomalyConfig
	if err := json.Unmarshal(val, &config); err != nil {
		return model.ProtocolAnomalyConfig{}, err
	}

	return config, nil
}

func (r *SettingsRepository) UpdateProtocolAnomalyConfig(config model.ProtocolAnomalyConfig) error {
	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('protocol_anomaly_config', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	return err
}

func (r *SettingsRepository) GetIPReputationConfig() (model.IPReputationConfig, error) {
	var val []byte
	err := r.db.QueryRow("SELECT value FROM settings WHERE key = 'ip_reputation_config'").Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.DefaultIPReputationConfig(), nil
		}
		return model.IPReputationConfig{}, err
	}

	var config model.IPReputationConfig
	if err := json.Unmarshal(val, &config); err != nil {
		return model.IPReputationConfig{}, err
	}

	return config, nil
}

func (r *SettingsRepository) UpdateIPReputationConfig(config model.IPReputationConfig) error {
	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('ip_reputation_config', $1, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()
	`, val)
	return err
}
