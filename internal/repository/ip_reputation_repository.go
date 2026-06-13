package repository

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/model"
)

type IPReputationRepository struct {
	db *sql.DB
}

func NewIPReputationRepository(db *sql.DB) *IPReputationRepository {
	return &IPReputationRepository{db: db}
}

func (r *IPReputationRepository) List() ([]*model.IPReputationEntry, error) {
	rows, err := r.db.Query(`
		SELECT id, entry_type, value, score, COALESCE(category, ''), description, enabled, created_at, updated_at
		FROM ip_reputation_entries ORDER BY id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query ip reputation entries: %w", err)
	}
	defer rows.Close()

	var entries []*model.IPReputationEntry
	for rows.Next() {
		e := &model.IPReputationEntry{}
		if err := rows.Scan(&e.ID, &e.EntryType, &e.Value, &e.Score, &e.Category, &e.Description, &e.Enabled, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan ip reputation entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (r *IPReputationRepository) GetByID(id int) (*model.IPReputationEntry, error) {
	e := &model.IPReputationEntry{}
	err := r.db.QueryRow(`
		SELECT id, entry_type, value, score, COALESCE(category, ''), description, enabled, created_at, updated_at
		FROM ip_reputation_entries WHERE id = $1
	`, id).Scan(&e.ID, &e.EntryType, &e.Value, &e.Score, &e.Category, &e.Description, &e.Enabled, &e.CreatedAt, &e.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ip reputation entry not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ip reputation entry: %w", err)
	}
	return e, nil
}

func (r *IPReputationRepository) Create(e *model.IPReputationEntry) error {
	now := time.Now()
	err := r.db.QueryRow(`
		INSERT INTO ip_reputation_entries (entry_type, value, score, category, description, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`, e.EntryType, e.Value, e.Score, e.Category, e.Description, e.Enabled, now, now).
		Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create ip reputation entry: %w", err)
	}
	return nil
}

func (r *IPReputationRepository) Update(e *model.IPReputationEntry) error {
	now := time.Now()
	result, err := r.db.Exec(`
		UPDATE ip_reputation_entries
		SET entry_type = $1, value = $2, score = $3, category = $4, description = $5, enabled = $6, updated_at = $7
		WHERE id = $8
	`, e.EntryType, e.Value, e.Score, e.Category, e.Description, e.Enabled, now, e.ID)
	if err != nil {
		return fmt.Errorf("failed to update ip reputation entry: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("ip reputation entry not found")
	}
	e.UpdatedAt = now
	return nil
}

func (r *IPReputationRepository) Delete(id int) error {
	result, err := r.db.Exec(`DELETE FROM ip_reputation_entries WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete ip reputation entry: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("ip reputation entry not found")
	}
	return nil
}

func (r *IPReputationRepository) BulkDelete(ids []int) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := `DELETE FROM ip_reputation_entries WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to bulk delete ip reputation entries: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

func (r *IPReputationRepository) BulkUpdateScore(ids []int, score int) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+1)
	args[0] = score
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	query := `UPDATE ip_reputation_entries SET score = $1, updated_at = NOW() WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to bulk update ip reputation scores: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

func (r *IPReputationRepository) ListEnabled() ([]*model.IPReputationEntry, error) {
	rows, err := r.db.Query(`
		SELECT id, entry_type, value, score, COALESCE(category, ''), description, enabled, created_at, updated_at
		FROM ip_reputation_entries WHERE enabled = true ORDER BY id ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query enabled ip reputation entries: %w", err)
	}
	defer rows.Close()

	var entries []*model.IPReputationEntry
	for rows.Next() {
		e := &model.IPReputationEntry{}
		if err := rows.Scan(&e.ID, &e.EntryType, &e.Value, &e.Score, &e.Category, &e.Description, &e.Enabled, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan ip reputation entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (r *IPReputationRepository) Upsert(e *model.IPReputationEntry) (bool, error) {
	now := time.Now()
	var id int
	err := r.db.QueryRow(`
		INSERT INTO ip_reputation_entries (entry_type, value, score, category, description, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (entry_type, value) DO NOTHING
		RETURNING id
	`, e.EntryType, e.Value, e.Score, e.Category, e.Description, e.Enabled, now, now).Scan(&id)
	if err != nil {
		return false, nil
	}
	e.ID = id
	e.CreatedAt = now
	e.UpdatedAt = now
	return true, nil
}
