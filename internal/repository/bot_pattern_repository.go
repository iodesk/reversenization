package repository

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/vibeswaf/waf/internal/model"
)


type BotPatternRepository struct {
	db *sql.DB
}


func NewBotPatternRepository(db *sql.DB) *BotPatternRepository {
	return &BotPatternRepository{db: db}
}


func (r *BotPatternRepository) GetAllPatterns() ([]model.BotPattern, error) {
	query := `
		SELECT id, pattern_type, pattern, score, verify_ip, enabled, description, created_at, updated_at
		FROM bot_patterns
		WHERE enabled = true
		ORDER BY pattern_type, score DESC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []model.BotPattern
	for rows.Next() {
		var p model.BotPattern
		err := rows.Scan(
			&p.ID, &p.PatternType, &p.Pattern, &p.Score, &p.VerifyIP,
			&p.Enabled, &p.Description, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p)
	}

	return patterns, rows.Err()
}


func (r *BotPatternRepository) GetPatternsByType(patternType string) ([]model.BotPattern, error) {
	query := `
		SELECT id, pattern_type, pattern, score, verify_ip, enabled, description, created_at, updated_at
		FROM bot_patterns
		WHERE enabled = true AND pattern_type = $1
		ORDER BY score DESC
	`

	rows, err := r.db.Query(query, patternType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []model.BotPattern
	for rows.Next() {
		var p model.BotPattern
		err := rows.Scan(
			&p.ID, &p.PatternType, &p.Pattern, &p.Score, &p.VerifyIP,
			&p.Enabled, &p.Description, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, p)
	}

	return patterns, rows.Err()
}


func (r *BotPatternRepository) GetWhitelist() ([]model.BotWhitelist, error) {
	query := `
		SELECT id, ip_range, description, created_at
		FROM bot_whitelist
		WHERE enabled = true
		ORDER BY id
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var whitelist []model.BotWhitelist
	for rows.Next() {
		var w model.BotWhitelist
		err := rows.Scan(&w.ID, &w.IPRange, &w.Description, &w.CreatedAt)
		if err != nil {
			return nil, err
		}
		whitelist = append(whitelist, w)
	}

	return whitelist, rows.Err()
}


func (r *BotPatternRepository) AddPattern(pattern *model.BotPattern) error {
	query := `
		INSERT INTO bot_patterns (pattern_type, pattern, score, verify_ip, enabled, description)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`

	return r.db.QueryRow(
		query,
		pattern.PatternType, pattern.Pattern, pattern.Score,
		pattern.VerifyIP, pattern.Enabled, pattern.Description,
	).Scan(&pattern.ID, &pattern.CreatedAt, &pattern.UpdatedAt)
}


func (r *BotPatternRepository) UpdatePattern(pattern *model.BotPattern) error {
	query := `
		UPDATE bot_patterns
		SET pattern_type = $1, pattern = $2, score = $3, verify_ip = $4, 
		    enabled = $5, description = $6, updated_at = NOW()
		WHERE id = $7
	`

	_, err := r.db.Exec(
		query,
		pattern.PatternType, pattern.Pattern, pattern.Score,
		pattern.VerifyIP, pattern.Enabled, pattern.Description, pattern.ID,
	)
	return err
}


func (r *BotPatternRepository) DeletePattern(id int) error {
	query := `DELETE FROM bot_patterns WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}

func (r *BotPatternRepository) BulkDeletePatterns(ids []int) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := `DELETE FROM bot_patterns WHERE id IN (` + strings.Join(placeholders, ",") + `)`
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return n, nil
}


func (r *BotPatternRepository) AddWhitelist(whitelist *model.BotWhitelist) error {
	query := `
		INSERT INTO bot_whitelist (ip_range, description)
		VALUES ($1, $2)
		RETURNING id, created_at
	`

	return r.db.QueryRow(query, whitelist.IPRange, whitelist.Description).
		Scan(&whitelist.ID, &whitelist.CreatedAt)
}


func (r *BotPatternRepository) DeleteWhitelist(id int) error {
	query := `DELETE FROM bot_whitelist WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}
