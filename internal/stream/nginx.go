package stream

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/domain/app"
)

type NginxManager struct {
	streamDir string
	appCfg    *config.AppConfig
}

func NewNginxManager() *NginxManager {
	streamDir := getEnv("STREAM_CONF_DIR", "/etc/openresty/stream.d")
	return &NginxManager{
		streamDir: streamDir,
		appCfg:    config.GetAppConfig(),
	}
}

func (m *NginxManager) GenerateConf(a *app.App) error {
	if !a.IsStream() {
		return nil
	}

	if err := os.MkdirAll(m.streamDir, 0755); err != nil {
		return fmt.Errorf("failed to create stream dir: %w", err)
	}

	confPath := filepath.Join(m.streamDir, fmt.Sprintf("app-%s.conf", a.ID))
	content := m.buildConf(a)

	if err := os.WriteFile(confPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write stream conf: %w", err)
	}

	m.appCfg.LogInfo("[STREAM] Generated conf for app=%s at %s", a.ID, confPath)
	return nil
}

func (m *NginxManager) RemoveConf(appID string) error {
	confPath := filepath.Join(m.streamDir, fmt.Sprintf("app-%s.conf", appID))

	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove stream conf: %w", err)
	}

	m.appCfg.LogInfo("[STREAM] Removed conf for app=%s", appID)
	return nil
}

func (m *NginxManager) Reload() error {
	cmd := exec.Command("nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.appCfg.LogError("[STREAM] Nginx reload failed: %v output=%s", err, string(output))
		return fmt.Errorf("nginx reload failed: %w", err)
	}

	m.appCfg.LogInfo("[STREAM] Nginx reloaded")
	return nil
}

func (m *NginxManager) TestConfig() error {
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.appCfg.LogError("[STREAM] Nginx config test failed: %v output=%s", err, string(output))
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}
	return nil
}

func (m *NginxManager) buildConf(a *app.App) string {
	var sb strings.Builder

	scheme := a.StreamScheme()
	listenPort := a.Config.ListenPort

	upstreams := make([]string, 0)
	for _, u := range a.Config.Upstreams {
		if u.Enabled {
			upstreams = append(upstreams, fmt.Sprintf("%s:%d", u.Host, u.Port))
		}
	}

	if len(upstreams) == 0 {
		return ""
	}

	sb.WriteString(fmt.Sprintf("# app: %s (%s)\n", a.ID, a.Domain))
	sb.WriteString(fmt.Sprintf("upstream stream_%s {\n", sanitizeID(a.ID)))

	if a.Config.LBMethod == "least-conn" || a.Config.LBMethod == "least_conn" {
		sb.WriteString("    least_conn;\n")
	}
	if a.Config.LBMethod == "ip-hash" || a.Config.LBMethod == "ip_hash" {
		sb.WriteString("    hash $remote_addr consistent;\n")
	}

	for _, u := range upstreams {
		sb.WriteString(fmt.Sprintf("    server %s;\n", u))
	}
	sb.WriteString("}\n\n")

	sb.WriteString("server {\n")
	if scheme == "udp" {
		sb.WriteString(fmt.Sprintf("    listen %d udp;\n", listenPort))
	} else {
		sb.WriteString(fmt.Sprintf("    listen %d;\n", listenPort))
	}

	sb.WriteString(fmt.Sprintf("    proxy_pass stream_%s;\n", sanitizeID(a.ID)))
	sb.WriteString("    proxy_connect_timeout 3s;\n")
	sb.WriteString("    proxy_timeout 300s;\n")

	if scheme == "tcp" {
		sb.WriteString("    proxy_socket_keepalive on;\n")
	}

	sb.WriteString("}\n")

	return sb.String()
}

func sanitizeID(id string) string {
	return strings.ReplaceAll(id, "-", "_")
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
