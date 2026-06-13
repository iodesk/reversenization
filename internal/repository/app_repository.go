package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vibeswaf/waf/internal/domain/app"
)


type appRepository struct {
	db *sql.DB
}


func NewAppRepository(db *sql.DB) AppRepository {
	return &appRepository{db: db}
}


func (r *appRepository) Create(a *app.App) error {
	query := `
		INSERT INTO applications (
			app_id, domain, config
		) VALUES ($1, $2, $3)
		RETURNING created_at, updated_at
	`

	configBytes, err := json.Marshal(a.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal app config: %w", err)
	}

	err = r.db.QueryRow(
		query,
		a.ID, a.Domain, configBytes,
	).Scan(&a.CreatedAt, &a.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create app: %w", err)
	}

	return nil
}


func (r *appRepository) Update(a *app.App) error {
	query := `
		UPDATE applications SET
			domain = $1, config = $2, updated_at = $3
		WHERE app_id = $4
	`

	configBytes, err := json.Marshal(a.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal app config: %w", err)
	}

	result, err := r.db.Exec(
		query,
		a.Domain, configBytes, time.Now(), a.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update app: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("app not found")
	}

	return nil
}


func (r *appRepository) Delete(id string) error {
	query := `DELETE FROM applications WHERE app_id = $1`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("app not found")
	}

	return nil
}


func (r *appRepository) GetByID(id string) (*app.App, error) {
	query := `
		SELECT 
			app_id, domain, config, under_attack_mode, created_at, updated_at
		FROM applications
		WHERE app_id = $1
	`

	var a app.App
	var configBytes []byte
	err := r.db.QueryRow(query, id).Scan(
		&a.ID, &a.Domain, &configBytes, &a.UnderAttackMode, &a.CreatedAt, &a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, app.ErrAppNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &a.Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	return &a, nil
}


func (r *appRepository) GetByDomain(domain string) (*app.App, error) {
	query := `
		SELECT 
			app_id, domain, config, under_attack_mode, created_at, updated_at
		FROM applications
		WHERE domain = $1
	`

	var a app.App
	var configBytes []byte
	err := r.db.QueryRow(query, domain).Scan(
		&a.ID, &a.Domain, &configBytes, &a.UnderAttackMode, &a.CreatedAt, &a.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, app.ErrAppNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	if len(configBytes) > 0 {
		if err := json.Unmarshal(configBytes, &a.Config); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}

	return &a, nil
}


func (r *appRepository) ListAll() ([]*app.App, error) {
	query := `
		SELECT 
			app_id, domain, config, under_attack_mode, created_at, updated_at
		FROM applications
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query apps: %w", err)
	}
	defer rows.Close()

	apps := make([]*app.App, 0)

	for rows.Next() {
		var a app.App
		var configBytes []byte
		if err := rows.Scan(
			&a.ID, &a.Domain, &configBytes, &a.UnderAttackMode, &a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			continue
		}
		if len(configBytes) > 0 {
			if err := json.Unmarshal(configBytes, &a.Config); err != nil {
				continue
			}
		}
		apps = append(apps, &a)
	}

	return apps, nil
}


func (r *appRepository) ToggleUnderAttackMode(appID string, enabled bool) error {
	query := `UPDATE applications SET under_attack_mode = $1, updated_at = NOW() WHERE app_id = $2`
	_, err := r.db.Exec(query, enabled, appID)
	return err
}
