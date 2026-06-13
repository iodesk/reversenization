package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/vibeswaf/waf/internal/domain/ip_access"
)

type IPAccessRepository interface {
	ListByApp(appID string) ([]*ip_access.IPAccessRule, error)
	GetByID(id int) (*ip_access.IPAccessRule, error)
	Create(req *ip_access.CreateRequest) (*ip_access.IPAccessRule, error)
	Update(id int, req *ip_access.UpdateRequest) (*ip_access.IPAccessRule, error)
	Delete(id int) error
	CheckIP(appID string, ip string) (*ip_access.IPAccessRule, error)
}

type ipAccessRepository struct {
	db *sql.DB
}

func NewIPAccessRepository(db *sql.DB) IPAccessRepository {
	return &ipAccessRepository{db: db}
}

func (r *ipAccessRepository) ListByApp(appID string) ([]*ip_access.IPAccessRule, error) {
	rows, err := r.db.Query(`
		SELECT id, app_id, ip_range, description, action, enabled, created_at, updated_at
		FROM ip_access_rules WHERE app_id = $1 ORDER BY id ASC
	`, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query ip access rules: %w", err)
	}
	defer rows.Close()

	var rules []*ip_access.IPAccessRule
	for rows.Next() {
		rule := &ip_access.IPAccessRule{}
		if err := rows.Scan(&rule.ID, &rule.AppID, &rule.IPRange, &rule.Description, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan ip access rule: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r *ipAccessRepository) GetByID(id int) (*ip_access.IPAccessRule, error) {
	rule := &ip_access.IPAccessRule{}
	err := r.db.QueryRow(`
		SELECT id, app_id, ip_range, description, action, enabled, created_at, updated_at
		FROM ip_access_rules WHERE id = $1
	`, id).Scan(&rule.ID, &rule.AppID, &rule.IPRange, &rule.Description, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ip access rule not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ip access rule: %w", err)
	}
	return rule, nil
}

func (r *ipAccessRepository) Create(req *ip_access.CreateRequest) (*ip_access.IPAccessRule, error) {
	now := time.Now()
	rule := &ip_access.IPAccessRule{}
	err := r.db.QueryRow(`
		INSERT INTO ip_access_rules (app_id, ip_range, description, action, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, app_id, ip_range, description, action, enabled, created_at, updated_at
	`, req.AppID, req.IPRange, req.Description, req.Action, req.Enabled, now, now).
		Scan(&rule.ID, &rule.AppID, &rule.IPRange, &rule.Description, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create ip access rule: %w", err)
	}
	return rule, nil
}

func (r *ipAccessRepository) Update(id int, req *ip_access.UpdateRequest) (*ip_access.IPAccessRule, error) {
	query := `UPDATE ip_access_rules SET updated_at = $1`
	args := []interface{}{time.Now()}
	i := 2

	if req.IPRange != "" {
		query += fmt.Sprintf(", ip_range = $%d", i)
		args = append(args, req.IPRange)
		i++
	}
	if req.Description != "" {
		query += fmt.Sprintf(", description = $%d", i)
		args = append(args, req.Description)
		i++
	}
	if req.Action != "" {
		query += fmt.Sprintf(", action = $%d", i)
		args = append(args, req.Action)
		i++
	}
	if req.Enabled != nil {
		query += fmt.Sprintf(", enabled = $%d", i)
		args = append(args, *req.Enabled)
		i++
	}
	query += fmt.Sprintf(" WHERE id = $%d RETURNING id, app_id, ip_range, description, action, enabled, created_at, updated_at", i)
	args = append(args, id)

	rule := &ip_access.IPAccessRule{}
	err := r.db.QueryRow(query, args...).
		Scan(&rule.ID, &rule.AppID, &rule.IPRange, &rule.Description, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ip access rule not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update ip access rule: %w", err)
	}
	return rule, nil
}

func (r *ipAccessRepository) Delete(id int) error {
	result, err := r.db.Exec(`DELETE FROM ip_access_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete ip access rule: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("ip access rule not found")
	}
	return nil
}

func (r *ipAccessRepository) CheckIP(appID string, ip string) (*ip_access.IPAccessRule, error) {
	rule := &ip_access.IPAccessRule{}
	err := r.db.QueryRow(`
		SELECT id, app_id, ip_range, description, action, enabled, created_at, updated_at
		FROM ip_access_rules
		WHERE app_id = $1 AND enabled = true AND $2::inet <<= ip_range
		ORDER BY id ASC LIMIT 1
	`, appID, ip).Scan(&rule.ID, &rule.AppID, &rule.IPRange, &rule.Description, &rule.Action, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to check ip: %w", err)
	}
	return rule, nil
}
