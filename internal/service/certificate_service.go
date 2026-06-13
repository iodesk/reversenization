package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/acme"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
)

type CertificateService struct {
	repo        *repository.CertificateRepository
	acmeService *acme.Service
	certDir     string
}

func NewCertificateService(repo *repository.CertificateRepository, acmeService *acme.Service) *CertificateService {
	certDir := os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "/opt/certs"
	}
	
	return &CertificateService{
		repo:        repo,
		acmeService: acmeService,
		certDir:     certDir,
	}
}

func (s *CertificateService) ListAll() ([]*model.CertificateInfo, error) {
	certs, err := s.repo.ListAll()
	if err != nil {
		return nil, err
	}

	infos := make([]*model.CertificateInfo, len(certs))
	for i, cert := range certs {
		infos[i] = s.toCertificateInfo(cert)
	}

	return infos, nil
}

func (s *CertificateService) ListByAppID(appID string) ([]*model.CertificateInfo, error) {
	certs, err := s.repo.ListByAppID(appID)
	if err != nil {
		return nil, err
	}

	infos := make([]*model.CertificateInfo, len(certs))
	for i, cert := range certs {
		infos[i] = s.toCertificateInfo(cert)
	}

	return infos, nil
}

func (s *CertificateService) GetByDomain(domain string) (*model.CertificateInfo, error) {
	cert, err := s.repo.GetByDomain(domain)
	if err != nil {
		return nil, err
	}

	return s.toCertificateInfo(cert), nil
}

func (s *CertificateService) RenewCertificate(domain string) error {
	if s.acmeService == nil {
		return fmt.Errorf("ACME service not available - acme.sh not installed")
	}

	cert, err := s.repo.GetByDomain(domain)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	config.GetAppConfig().LogInfo("[CertService] Starting manual renewal for %s", domain)

	s.logAction(cert.ID, domain, "renew", "started", "Manual renewal initiated")

	if err := s.acmeService.IssueAsync(domain); err != nil {
		s.logAction(cert.ID, domain, "renew", "failed", err.Error())
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	now := time.Now()
	cert.LastRenewAt = &now
	cert.LastRenewStatus = "pending"
	cert.UpdatedAt = now

	if err := s.repo.Update(cert); err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	s.logAction(cert.ID, domain, "renew", "pending", "Renewal request submitted")

	return nil
}

func (s *CertificateService) ValidateCertificate(domain string) (*model.CertificateInfo, error) {
	config.GetAppConfig().LogInfo("[CertService] Validating certificate for %s", domain)

	// Check if certificate files exist
	certPath := fmt.Sprintf("%s/%s/fullchain.pem", s.certDir, domain)
	
	if _, err := os.Stat(certPath); err != nil {
		return nil, fmt.Errorf("certificate not found on filesystem")
	}

	// Read expiry date using openssl
	cmd := exec.Command("openssl", "x509", "-enddate", "-noout", "-in", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to check certificate expiry: %w", err)
	}

	dateStr := strings.TrimPrefix(string(output), "notAfter=")
	dateStr = strings.TrimSpace(dateStr)

	expiryDate, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry date: %w", err)
	}

	issuer, err := s.getCertificateIssuer(domain)
	if err != nil {
		config.GetAppConfig().LogWarn("[CertService] Failed to get issuer for %s: %v", domain, err)
		issuer = "Unknown"
	}

	cert, err := s.repo.GetByDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("certificate not found in database: %w", err)
	}

	cert.Status = s.determineStatus(expiryDate)
	cert.Issuer = issuer
	cert.ExpiresAt = expiryDate
	cert.UpdatedAt = time.Now()

	if err := s.repo.Update(cert); err != nil {
		return nil, fmt.Errorf("failed to update certificate: %w", err)
	}

	s.logAction(cert.ID, domain, "validate", "success", fmt.Sprintf("Certificate validated, expires: %s", expiryDate.Format("2006-01-02")))

	info := s.toCertificateInfo(cert)
	daysUntilExpiry := int(time.Until(expiryDate).Hours() / 24)
	info.IsExpiringSoon = daysUntilExpiry < 30

	return info, nil
}

func (s *CertificateService) ToggleAutoRenew(domain string, enabled bool) error {
	cert, err := s.repo.GetByDomain(domain)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	if err := s.repo.ToggleAutoRenew(cert.ID, enabled); err != nil {
		return err
	}

	action := "disabled"
	if enabled {
		action = "enabled"
	}

	s.logAction(cert.ID, domain, "auto_renew", action, fmt.Sprintf("Auto-renew %s", action))

	config.GetAppConfig().LogInfo("[CertService] Auto-renew %s for %s", action, domain)

	return nil
}

func (s *CertificateService) GetLogs(domain string, limit int) ([]*model.CertificateLog, error) {
	return s.repo.GetLogsByDomain(domain, limit)
}

func (s *CertificateService) DeleteCertificate(domain string) error {
	config.GetAppConfig().LogInfo("[CertService] Deleting certificate for %s", domain)

	cert, err := s.repo.GetByDomain(domain)
	if err != nil {
		return fmt.Errorf("certificate not found: %w", err)
	}

	if err := s.repo.DeleteByDomain(domain); err != nil {
		config.GetAppConfig().LogError("[CertService] Failed to delete certificate %s: %v", domain, err)
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	config.GetAppConfig().LogInfo("[CertService] Certificate %s deleted (ID: %d)", domain, cert.ID)
	return nil
}

func (s *CertificateService) BulkDeleteCertificates(domains []string) (int, error) {
	if len(domains) == 0 {
		return 0, fmt.Errorf("no domains provided")
	}

	config.GetAppConfig().LogInfo("[CertService] Bulk delete requested for %d certificates", len(domains))

	deleted, err := s.repo.BulkDelete(domains)
	if err != nil {
		config.GetAppConfig().LogError("[CertService] Bulk delete failed: %v", err)
		return 0, fmt.Errorf("failed to bulk delete certificates: %w", err)
	}

	config.GetAppConfig().LogInfo("[CertService] Bulk delete completed: %d/%d certificates deleted", deleted, len(domains))
	return deleted, nil
}

func (s *CertificateService) SyncFromACME(domain, appID string) error {
	config.GetAppConfig().LogDebug("[CertService] Syncing certificate for domain: %s", domain)
	
	// Check if certificate files exist
	certPath := fmt.Sprintf("%s/%s/fullchain.pem", s.certDir, domain)
	keyPath := fmt.Sprintf("%s/%s/key.pem", s.certDir, domain)
	
	if _, err := os.Stat(certPath); err != nil {
		config.GetAppConfig().LogError("[CertService] Certificate file not found: %s - %v", certPath, err)
		return fmt.Errorf("certificate not found on filesystem: %w", err)
	}
	
	if _, err := os.Stat(keyPath); err != nil {
		config.GetAppConfig().LogError("[CertService] Key file not found: %s - %v", keyPath, err)
		return fmt.Errorf("key not found on filesystem: %w", err)
	}

	config.GetAppConfig().LogDebug("[CertService] Certificate files found for %s", domain)

	// Read expiry date using openssl
	cmd := exec.Command("openssl", "x509", "-enddate", "-noout", "-in", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		config.GetAppConfig().LogError("[CertService] Failed to read expiry for %s: %v", domain, err)
		return fmt.Errorf("failed to check certificate expiry: %w", err)
	}

	dateStr := strings.TrimPrefix(string(output), "notAfter=")
	dateStr = strings.TrimSpace(dateStr)

	expiryDate, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr)
	if err != nil {
		config.GetAppConfig().LogError("[CertService] Failed to parse expiry date for %s: %v", domain, err)
		return fmt.Errorf("failed to parse expiry date: %w", err)
	}

	config.GetAppConfig().LogDebug("[CertService] Certificate expires at: %s", expiryDate.Format("2006-01-02"))

	issuer, err := s.getCertificateIssuer(domain)
	if err != nil {
		config.GetAppConfig().LogWarn("[CertService] Failed to get issuer for %s: %v", domain, err)
		issuer = "Let's Encrypt"
	}

	cert, err := s.repo.GetByDomain(domain)
	if err != nil {
		// Create new certificate record
		config.GetAppConfig().LogDebug("[CertService] Creating new certificate record for %s", domain)
		
		cert = &model.Certificate{
			Domain:          domain,
			AppID:           appID,
			Status:          s.determineStatus(expiryDate),
			Issuer:          issuer,
			IssuedAt:        time.Now(),
			ExpiresAt:       expiryDate,
			AutoRenew:       true,
			LastRenewStatus: "success",
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}

		if err := s.repo.Create(cert); err != nil {
			config.GetAppConfig().LogError("[CertService] Failed to create certificate record for %s: %v", domain, err)
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		s.logAction(cert.ID, domain, "sync", "success", "Certificate synced from filesystem")
		config.GetAppConfig().LogInfo("[CertService] Created certificate record for %s (expires: %s)", domain, expiryDate.Format("2006-01-02"))
	} else {
		// Update existing certificate record
		config.GetAppConfig().LogDebug("[CertService] Updating existing certificate record for %s", domain)
		
		cert.Status = s.determineStatus(expiryDate)
		cert.Issuer = issuer
		cert.ExpiresAt = expiryDate
		cert.UpdatedAt = time.Now()

		if err := s.repo.Update(cert); err != nil {
			config.GetAppConfig().LogError("[CertService] Failed to update certificate record for %s: %v", domain, err)
			return fmt.Errorf("failed to update certificate: %w", err)
		}

		s.logAction(cert.ID, domain, "sync", "success", "Certificate updated from filesystem")
		config.GetAppConfig().LogInfo("[CertService] Updated certificate record for %s (expires: %s)", domain, expiryDate.Format("2006-01-02"))
	}

	return nil
}

func (s *CertificateService) SyncAllFromFilesystem() error {
	config.GetAppConfig().LogInfo("[CertService] Starting filesystem sync from: %s", s.certDir)
	
	entries, err := os.ReadDir(s.certDir)
	if err != nil {
		config.GetAppConfig().LogError("[CertService] Failed to read cert directory %s: %v", s.certDir, err)
		return fmt.Errorf("failed to read cert directory: %w", err)
	}

	config.GetAppConfig().LogDebug("[CertService] Found %d entries in cert directory", len(entries))

	synced := 0
	skipped := 0
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		domain := entry.Name()
		config.GetAppConfig().LogDebug("[CertService] Processing domain: %s", domain)
		
		// Check if certificate files exist
		certPath := fmt.Sprintf("%s/%s/fullchain.pem", s.certDir, domain)
		keyPath := fmt.Sprintf("%s/%s/key.pem", s.certDir, domain)
		
		certInfo, certErr := os.Stat(certPath)
		keyInfo, keyErr := os.Stat(keyPath)
		
		if certErr != nil || keyErr != nil {
			config.GetAppConfig().LogDebug("[CertService] Skipping %s: missing certificate files (cert: %v, key: %v)", domain, certErr, keyErr)
			skipped++
			continue
		}
		
		if certInfo.Size() == 0 || keyInfo.Size() == 0 {
			config.GetAppConfig().LogDebug("[CertService] Skipping %s: empty certificate files", domain)
			skipped++
			continue
		}

		// Try to sync
		if err := s.SyncFromACME(domain, ""); err != nil {
			config.GetAppConfig().LogWarn("[CertService] Failed to sync %s: %v", domain, err)
			skipped++
			continue
		}

		synced++
	}

	config.GetAppConfig().LogInfo("[CertService] Sync complete: %d synced, %d skipped", synced, skipped)
	return nil
}

func (s *CertificateService) toCertificateInfo(cert *model.Certificate) *model.CertificateInfo {
	daysUntilExpiry := int(time.Until(cert.ExpiresAt).Hours() / 24)
	isExpiringSoon := daysUntilExpiry < 30

	return &model.CertificateInfo{
		Domain:          cert.Domain,
		Status:          cert.Status,
		Issuer:          cert.Issuer,
		ExpiresAt:       cert.ExpiresAt,
		DaysUntilExpiry: daysUntilExpiry,
		AutoRenew:       cert.AutoRenew,
		IsExpiringSoon:  isExpiringSoon,
		LastRenewAt:     cert.LastRenewAt,
		LastRenewStatus: cert.LastRenewStatus,
	}
}

func (s *CertificateService) determineStatus(expiresAt time.Time) string {
	daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)

	if daysUntilExpiry < 0 {
		return "expired"
	} else if daysUntilExpiry < 30 {
		return "expiring_soon"
	}

	return "valid"
}

func (s *CertificateService) getCertificateIssuer(domain string) (string, error) {
	certPath := fmt.Sprintf("%s/%s/fullchain.pem", s.certDir, domain)
	
	config.GetAppConfig().LogDebug("[CertService] Getting issuer for %s from %s", domain, certPath)

	cmd := exec.Command("openssl", "x509", "-issuer", "-noout", "-in", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		config.GetAppConfig().LogError("[CertService] Failed to get issuer: %v", err)
		return "", fmt.Errorf("failed to get certificate issuer: %w", err)
	}

	issuerStr := strings.TrimPrefix(string(output), "issuer=")
	issuerStr = strings.TrimSpace(issuerStr)

	if strings.Contains(issuerStr, "Let's Encrypt") {
		return "Let's Encrypt", nil
	} else if strings.Contains(issuerStr, "ZeroSSL") {
		return "ZeroSSL", nil
	}

	return issuerStr, nil
}

func (s *CertificateService) logAction(certID int, domain, action, status, message string) {
	log := &model.CertificateLog{
		CertID:    certID,
		Domain:    domain,
		Action:    action,
		Status:    status,
		Message:   message,
		CreatedAt: time.Now(),
	}

	if err := s.repo.CreateLog(log); err != nil {
		config.GetAppConfig().LogError("[CertService] Failed to create log: %v", err)
	}
}
