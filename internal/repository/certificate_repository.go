package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/vibeswaf/waf/internal/model"
)

type CertificateRepository struct {
	db *sql.DB
}

func NewCertificateRepository(db *sql.DB) *CertificateRepository {
	return &CertificateRepository{db: db}
}

func (r *CertificateRepository) Create(cert *model.Certificate) error {
	query := `
		INSERT INTO certificates (
			domain, app_id, status, issuer, issued_at, expires_at, 
			auto_renew, last_renew_status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING cert_id
	`

	err := r.db.QueryRow(
		query,
		cert.Domain,
		cert.AppID,
		cert.Status,
		cert.Issuer,
		cert.IssuedAt,
		cert.ExpiresAt,
		cert.AutoRenew,
		cert.LastRenewStatus,
		time.Now(),
		time.Now(),
	).Scan(&cert.ID)

	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	return nil
}

func (r *CertificateRepository) Update(cert *model.Certificate) error {
	query := `
		UPDATE certificates SET
			status = $1, issuer = $2, issued_at = $3, expires_at = $4,
			auto_renew = $5, last_renew_at = $6, last_renew_status = $7,
			updated_at = $8
		WHERE cert_id = $9
	`

	result, err := r.db.Exec(
		query,
		cert.Status,
		cert.Issuer,
		cert.IssuedAt,
		cert.ExpiresAt,
		cert.AutoRenew,
		cert.LastRenewAt,
		cert.LastRenewStatus,
		time.Now(),
		cert.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

func (r *CertificateRepository) Delete(id int) error {
	query := `DELETE FROM certificates WHERE cert_id = $1`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

func (r *CertificateRepository) DeleteByDomain(domain string) error {
	query := `DELETE FROM certificates WHERE domain = $1`

	result, err := r.db.Exec(query, domain)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

func (r *CertificateRepository) BulkDelete(domains []string) (int, error) {
	if len(domains) == 0 {
		return 0, nil
	}

	query := `DELETE FROM certificates WHERE domain = ANY($1)`

	result, err := r.db.Exec(query, pq.Array(domains))
	if err != nil {
		return 0, fmt.Errorf("failed to bulk delete certificates: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rows), nil
}

func (r *CertificateRepository) GetByID(id int) (*model.Certificate, error) {
	query := `
		SELECT
			cert_id, domain, app_id, status, issuer, issued_at, expires_at,
			auto_renew, last_renew_at, last_renew_status, created_at, updated_at
		FROM certificates
		WHERE cert_id = $1
	`

	cert := &model.Certificate{}
	err := r.db.QueryRow(query, id).Scan(
		&cert.ID,
		&cert.Domain,
		&cert.AppID,
		&cert.Status,
		&cert.Issuer,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&cert.AutoRenew,
		&cert.LastRenewAt,
		&cert.LastRenewStatus,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return cert, nil
}

func (r *CertificateRepository) GetByDomain(domain string) (*model.Certificate, error) {
	query := `
		SELECT
			cert_id, domain, app_id, status, issuer, issued_at, expires_at,
			auto_renew, last_renew_at, last_renew_status, created_at, updated_at
		FROM certificates
		WHERE domain = $1
	`

	cert := &model.Certificate{}
	err := r.db.QueryRow(query, domain).Scan(
		&cert.ID,
		&cert.Domain,
		&cert.AppID,
		&cert.Status,
		&cert.Issuer,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&cert.AutoRenew,
		&cert.LastRenewAt,
		&cert.LastRenewStatus,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return cert, nil
}

func (r *CertificateRepository) ListAll() ([]*model.Certificate, error) {
	query := `
		SELECT
			cert_id, domain, app_id, status, issuer, issued_at, expires_at,
			auto_renew, last_renew_at, last_renew_status, created_at, updated_at
		FROM certificates
		ORDER BY expires_at ASC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	certs := make([]*model.Certificate, 0)

	for rows.Next() {
		cert := &model.Certificate{}
		if err := rows.Scan(
			&cert.ID,
			&cert.Domain,
			&cert.AppID,
			&cert.Status,
			&cert.Issuer,
			&cert.IssuedAt,
			&cert.ExpiresAt,
			&cert.AutoRenew,
			&cert.LastRenewAt,
			&cert.LastRenewStatus,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificates: %w", err)
	}

	return certs, nil
}

func (r *CertificateRepository) ListByAppID(appID string) ([]*model.Certificate, error) {
	query := `
		SELECT
			cert_id, domain, app_id, status, issuer, issued_at, expires_at,
			auto_renew, last_renew_at, last_renew_status, created_at, updated_at
		FROM certificates
		WHERE app_id = $1
		ORDER BY expires_at ASC
	`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificates: %w", err)
	}
	defer rows.Close()

	certs := make([]*model.Certificate, 0)

	for rows.Next() {
		cert := &model.Certificate{}
		if err := rows.Scan(
			&cert.ID,
			&cert.Domain,
			&cert.AppID,
			&cert.Status,
			&cert.Issuer,
			&cert.IssuedAt,
			&cert.ExpiresAt,
			&cert.AutoRenew,
			&cert.LastRenewAt,
			&cert.LastRenewStatus,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificates: %w", err)
	}

	return certs, nil
}

func (r *CertificateRepository) ToggleAutoRenew(id int, enabled bool) error {
	query := `UPDATE certificates SET auto_renew = $1, updated_at = $2 WHERE cert_id = $3`

	result, err := r.db.Exec(query, enabled, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to toggle auto renew: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("certificate not found")
	}

	return nil
}

func (r *CertificateRepository) CreateLog(log *model.CertificateLog) error {
	query := `
		INSERT INTO certificate_logs (
			cert_id, domain, action, status, message, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING log_id
	`

	err := r.db.QueryRow(
		query,
		log.CertID,
		log.Domain,
		log.Action,
		log.Status,
		log.Message,
		time.Now(),
	).Scan(&log.ID)

	if err != nil {
		return fmt.Errorf("failed to create certificate log: %w", err)
	}

	return nil
}

func (r *CertificateRepository) GetLogsByCertID(certID int, limit int) ([]*model.CertificateLog, error) {
	query := `
		SELECT
			log_id, cert_id, domain, action, status, message, created_at
		FROM certificate_logs
		WHERE cert_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.Query(query, certID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*model.CertificateLog, 0)

	for rows.Next() {
		log := &model.CertificateLog{}
		if err := rows.Scan(
			&log.ID,
			&log.CertID,
			&log.Domain,
			&log.Action,
			&log.Status,
			&log.Message,
			&log.CreatedAt,
		); err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

func (r *CertificateRepository) GetLogsByDomain(domain string, limit int) ([]*model.CertificateLog, error) {
	query := `
		SELECT
			log_id, cert_id, domain, action, status, message, created_at
		FROM certificate_logs
		WHERE domain = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.Query(query, domain, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query certificate logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*model.CertificateLog, 0)

	for rows.Next() {
		log := &model.CertificateLog{}
		if err := rows.Scan(
			&log.ID,
			&log.CertID,
			&log.Domain,
			&log.Action,
			&log.Status,
			&log.Message,
			&log.CreatedAt,
		); err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}
