package acme

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/vibeswaf/waf/internal/config"
	"path/filepath"
	"strings"
	"sync"
	"time"
)


type Service struct {
	acmeShPath string
	acmeHome   string
	certDir    string
	email      string
	mu         sync.Mutex
	pending    map[string]bool
}


func NewService(certDir, email string) *Service {
	acmeShPath := os.Getenv("ACME_SH_PATH")
	if acmeShPath == "" {

		homeDir, _ := os.UserHomeDir()
		acmeShPath = filepath.Join(homeDir, ".acme.sh", "acme.sh")
	}

	// acme.sh needs HOME / LE_WORKING_DIR to locate its account config and
	// per-domain storage. systemd runs the service without HOME set, so derive
	// the acme working dir from the script path (e.g. /opt/wafer/.acme.sh).
	acmeHome := filepath.Dir(acmeShPath)

	return &Service{
		acmeShPath: acmeShPath,
		acmeHome:   acmeHome,
		certDir:    certDir,
		email:      email,
		pending:    make(map[string]bool),
	}
}

// acmeEnv returns the environment for acme.sh exec calls, ensuring HOME and
// LE_WORKING_DIR point at the acme.sh install dir even when the parent process
// (systemd service) has no HOME set.
func (s *Service) acmeEnv() []string {
	home := filepath.Dir(s.acmeHome) // parent of .acme.sh → user home
	return append(os.Environ(),
		"HOME="+home,
		"LE_WORKING_DIR="+s.acmeHome,
	)
}


func (s *Service) IsInstalled() bool {
	_, err := os.Stat(s.acmeShPath)
	return err == nil
}


func (s *Service) HasCertificate(domain string) bool {
	certPath := filepath.Join(s.certDir, domain, "fullchain.pem")
	keyPath := filepath.Join(s.certDir, domain, "key.pem")

	certInfo, certErr := os.Stat(certPath)
	keyInfo, keyErr := os.Stat(keyPath)

	if certErr != nil || keyErr != nil {
		return false
	}


	return certInfo.Size() > 0 && keyInfo.Size() > 0
}


func (s *Service) IssueAsync(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()


	if s.pending[domain] {
		return fmt.Errorf("certificate request already pending for %s", domain)
	}


	if s.HasCertificate(domain) {
		return nil
	}


	s.pending[domain] = true


	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.pending, domain)
			s.mu.Unlock()
		}()

		if err := s.issue(domain); err != nil {
			config.GetAppConfig().LogError("[ACME] Failed to issue certificate for %s: %v", domain, err)
		} else {
			config.GetAppConfig().LogInfo("[ACME] Certificate issued successfully for %s", domain)
		}
	}()

	return nil
}


func (s *Service) issue(domain string) error {
	if !s.IsInstalled() {
		return fmt.Errorf("acme.sh not installed at %s", s.acmeShPath)
	}


	domainCertDir := filepath.Join(s.certDir, domain)
	if err := os.MkdirAll(domainCertDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}



	issueCmd := exec.Command(
		s.acmeShPath,
		"--issue",
		"-d", domain,
		"--standalone",
		"--httpport", "8080",
	)
	issueCmd.Env = s.acmeEnv()

	output, err := issueCmd.CombinedOutput()
	if err != nil {

		if strings.Contains(string(output), "already issued") {
			return s.installCert(domain)
		}
		return fmt.Errorf("failed to issue certificate: %w\nOutput: %s", err, string(output))
	}


	return s.installCert(domain)
}


func (s *Service) installCert(domain string) error {
	domainCertDir := filepath.Join(s.certDir, domain)
	keyPath := filepath.Join(domainCertDir, "key.pem")
	fullchainPath := filepath.Join(domainCertDir, "fullchain.pem")

	// OpenResty loads certificates dynamically via ssl_certificate_by_lua
	// (ssl.lua) with a TTL cache. No service reload is needed when a new cert
	// is installed, so reloadcmd is a no-op (":") to keep acme.sh from failing.
	installCmd := exec.Command(
		s.acmeShPath,
		"--install-cert",
		"-d", domain,
		"--key-file", keyPath,
		"--fullchain-file", fullchainPath,
		"--reloadcmd", ":",
	)
	installCmd.Env = s.acmeEnv()

	output, err := installCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install certificate: %w\nOutput: %s", err, string(output))
	}


	os.Chmod(keyPath, 0644)
	os.Chmod(fullchainPath, 0644)

	return nil
}


func (s *Service) RenewAll() error {
	if !s.IsInstalled() {
		return fmt.Errorf("acme.sh not installed")
	}

	renewCmd := exec.Command(s.acmeShPath, "--renew-all")
	renewCmd.Env = s.acmeEnv()
	output, err := renewCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to renew certificates: %w\nOutput: %s", err, string(output))
	}

	config.GetAppConfig().LogInfo("[ACME] Certificate renewal completed")
	return nil
}


func (s *Service) CheckExpiry(domain string) (bool, time.Time, error) {
	certPath := filepath.Join(s.certDir, domain, "fullchain.pem")


	cmd := exec.Command("openssl", "x509", "-enddate", "-noout", "-in", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to check certificate expiry: %w", err)
	}


	dateStr := strings.TrimPrefix(string(output), "notAfter=")
	dateStr = strings.TrimSpace(dateStr)

	expiryDate, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to parse expiry date: %w", err)
	}


	daysUntilExpiry := time.Until(expiryDate).Hours() / 24
	isExpiringSoon := daysUntilExpiry < 30

	return isExpiringSoon, expiryDate, nil
}


func (s *Service) AutoProvision(domain string) {

	if s.HasCertificate(domain) {
		return
	}


	if err := s.IssueAsync(domain); err != nil {
		config.GetAppConfig().LogError("[ACME] Failed to start certificate provisioning for %s: %v", domain, err)
	} else {
		config.GetAppConfig().LogInfo("[ACME] Started certificate provisioning for %s", domain)
	}
}
