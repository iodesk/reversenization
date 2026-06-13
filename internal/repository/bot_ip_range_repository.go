package repository

import (
	"database/sql"
	"encoding/json"

	"github.com/vibeswaf/waf/internal/model"
)

type BotIPRangeRepository struct {
	db *sql.DB
}

func NewBotIPRangeRepository(db *sql.DB) *BotIPRangeRepository {
	return &BotIPRangeRepository{db: db}
}

func (r *BotIPRangeRepository) GetAll() ([]model.BotIPRange, error) {
	query := `
		SELECT id, name, source_type, url, ip_ranges, enabled, description, last_fetched, created_at, updated_at
		FROM bot_ip_ranges
		ORDER BY name
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ranges []model.BotIPRange
	for rows.Next() {
		var item model.BotIPRange
		var ipRangesJSON string
		var lastFetched sql.NullTime
		err := rows.Scan(
			&item.ID, &item.Name, &item.SourceType, &item.URL,
			&ipRangesJSON, &item.Enabled, &item.Description,
			&lastFetched, &item.CreatedAt, &item.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if lastFetched.Valid {
			item.LastFetched = &lastFetched.Time
		}
		if ipRangesJSON != "" {
			json.Unmarshal([]byte(ipRangesJSON), &item.IPRanges)
		}
		if item.IPRanges == nil {
			item.IPRanges = []string{}
		}
		ranges = append(ranges, item)
	}

	return ranges, rows.Err()
}

func (r *BotIPRangeRepository) GetEnabled() ([]model.BotIPRange, error) {
	query := `
		SELECT id, name, source_type, url, ip_ranges, enabled, description, last_fetched, created_at, updated_at
		FROM bot_ip_ranges
		WHERE enabled = true
		ORDER BY name
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ranges []model.BotIPRange
	for rows.Next() {
		var item model.BotIPRange
		var ipRangesJSON string
		var lastFetched sql.NullTime
		err := rows.Scan(
			&item.ID, &item.Name, &item.SourceType, &item.URL,
			&ipRangesJSON, &item.Enabled, &item.Description,
			&lastFetched, &item.CreatedAt, &item.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if lastFetched.Valid {
			item.LastFetched = &lastFetched.Time
		}
		if ipRangesJSON != "" {
			json.Unmarshal([]byte(ipRangesJSON), &item.IPRanges)
		}
		if item.IPRanges == nil {
			item.IPRanges = []string{}
		}
		ranges = append(ranges, item)
	}

	return ranges, rows.Err()
}

func (r *BotIPRangeRepository) Create(item *model.BotIPRange) error {
	ipRangesJSON, err := json.Marshal(item.IPRanges)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO bot_ip_ranges (name, source_type, url, ip_ranges, enabled, description)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`

	return r.db.QueryRow(
		query,
		item.Name, item.SourceType, item.URL, string(ipRangesJSON),
		item.Enabled, item.Description,
	).Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
}

func (r *BotIPRangeRepository) Update(item *model.BotIPRange) error {
	ipRangesJSON, err := json.Marshal(item.IPRanges)
	if err != nil {
		return err
	}

	query := `
		UPDATE bot_ip_ranges
		SET name = $1, source_type = $2, url = $3, ip_ranges = $4,
		    enabled = $5, description = $6, updated_at = NOW()
		WHERE id = $7
	`

	_, err = r.db.Exec(
		query,
		item.Name, item.SourceType, item.URL, string(ipRangesJSON),
		item.Enabled, item.Description, item.ID,
	)
	return err
}

func (r *BotIPRangeRepository) UpdateIPRanges(id int, ipRanges []string) error {
	ipRangesJSON, err := json.Marshal(ipRanges)
	if err != nil {
		return err
	}

	query := `
		UPDATE bot_ip_ranges
		SET ip_ranges = $1, last_fetched = NOW(), updated_at = NOW()
		WHERE id = $2
	`

	_, err = r.db.Exec(query, string(ipRangesJSON), id)
	return err
}

func (r *BotIPRangeRepository) Delete(id int) error {
	query := `DELETE FROM bot_ip_ranges WHERE id = $1`
	_, err := r.db.Exec(query, id)
	return err
}
