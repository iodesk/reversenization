package service

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vibeswaf/waf/internal/acme"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/domain/app"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/stream"
)

// appSnapshot is the in-memory index of apps, swapped atomically on reload.
// Reads on the request path are lock-free atomic pointer loads.
type appSnapshot struct {
	byDomain map[string]*app.App
	byID     map[string]*app.App
}

type AppService struct {
	repo          repository.AppRepository
	acmeService   *acme.Service
	healthChecker *HealthCheckService
	streamProxy   *stream.Proxy
	nginxManager  *stream.NginxManager

	// snapshot is read via atomic load on every request — zero DB query.
	snapshot unsafe.Pointer // *appSnapshot
	stopCh   chan struct{}
}

func NewAppService(repo repository.AppRepository, acmeService *acme.Service, streamProxy *stream.Proxy, nginxManager *stream.NginxManager) *AppService {
	s := &AppService{
		repo:         repo,
		acmeService:  acmeService,
		streamProxy:  streamProxy,
		nginxManager: nginxManager,
		stopCh:       make(chan struct{}),
	}
	s.healthChecker = NewHealthCheckService(s)
	s.reloadSnapshot()
	go s.autoReload()
	return s
}

func (s *AppService) getSnapshot() *appSnapshot {
	return (*appSnapshot)(atomic.LoadPointer(&s.snapshot))
}

// reloadSnapshot rebuilds the in-memory app index from the database and swaps
// it atomically. Called at startup, on every mutation, and periodically.
func (s *AppService) reloadSnapshot() {
	apps, err := s.repo.ListAll()
	if err != nil {
		config.GetAppConfig().LogWarn("[AppService] Failed to reload app snapshot: %v", err)
		return
	}

	byDomain := make(map[string]*app.App, len(apps))
	byID := make(map[string]*app.App, len(apps))
	for _, a := range apps {
		byDomain[a.Domain] = a
		byID[a.ID] = a
	}

	atomic.StorePointer(&s.snapshot, unsafe.Pointer(&appSnapshot{byDomain: byDomain, byID: byID}))
}

func (s *AppService) autoReload() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.reloadSnapshot()
		}
	}
}

// Stop terminates the background reload goroutine.
func (s *AppService) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *AppService) CreateApp(a *app.App) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if a.IsStream() {
		if err := s.resolveStreamPort(a); err != nil {
			return err
		}
	}

	if err := s.repo.Create(a); err != nil {
		return fmt.Errorf("failed to create app: %w", err)
	}

	s.reloadSnapshot()

	config.GetAppConfig().LogInfo("[AppService] Created app: %s (domain: %s)", a.ID, a.Domain)

	if a.IsStream() {
		s.setupStream(a)
	} else {
		if s.acmeService != nil {
			s.acmeService.AutoProvision(a.Domain)
		}
		s.healthChecker.Start(a)
	}

	return nil
}

func (s *AppService) UpdateApp(a *app.App) error {
	if err := a.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if a.IsStream() {
		if err := s.resolveStreamPort(a); err != nil {
			return err
		}
	}

	if err := s.repo.Update(a); err != nil {
		return fmt.Errorf("failed to update app: %w", err)
	}

	s.reloadSnapshot()

	config.GetAppConfig().LogInfo("[AppService] Updated app: %s", a.ID)

	if a.IsStream() {
		s.streamProxy.StopForApp(a.ID)
		s.setupStream(a)
	} else {
		s.healthChecker.Stop(a.ID)
		s.healthChecker.Start(a)
	}

	return nil
}

func (s *AppService) DeleteApp(id string) error {
	existing, _ := s.repo.GetByID(id)

	if err := s.repo.Delete(id); err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	s.reloadSnapshot()

	config.GetAppConfig().LogInfo("[AppService] Deleted app: %s", id)

	if existing != nil && existing.IsStream() {
		s.streamProxy.StopForApp(id)
		s.nginxManager.RemoveConf(id)
		s.nginxManager.Reload()
	} else {
		s.healthChecker.Stop(id)
	}

	return nil
}

func (s *AppService) GetApp(id string) (*app.App, error) {
	if snap := s.getSnapshot(); snap != nil {
		if a, ok := snap.byID[id]; ok {
			return a, nil
		}
	}
	return s.repo.GetByID(id)
}

func (s *AppService) GetAppByDomain(domain string) (*app.App, error) {
	if snap := s.getSnapshot(); snap != nil {
		if a, ok := snap.byDomain[domain]; ok {
			return a, nil
		}
		return nil, app.ErrAppNotFound
	}
	return s.repo.GetByDomain(domain)
}

func (s *AppService) ListApps() ([]*app.App, error) {
	return s.repo.ListAll()
}

func (s *AppService) ToggleUnderAttackMode(appID string, enabled bool) error {
	if err := s.repo.ToggleUnderAttackMode(appID, enabled); err != nil {
		return err
	}
	s.reloadSnapshot()
	return nil
}

func (s *AppService) setupStream(a *app.App) {
	if err := s.nginxManager.GenerateConf(a); err != nil {
		config.GetAppConfig().LogError("[AppService] Failed to generate stream conf: %v", err)
		return
	}

	if err := s.nginxManager.TestConfig(); err != nil {
		config.GetAppConfig().LogError("[AppService] Nginx config test failed, rolling back: %v", err)
		s.nginxManager.RemoveConf(a.ID)
		return
	}

	if err := s.nginxManager.Reload(); err != nil {
		config.GetAppConfig().LogError("[AppService] Nginx reload failed: %v", err)
		return
	}

	if err := s.streamProxy.StartForApp(a); err != nil {
		config.GetAppConfig().LogError("[AppService] Failed to start stream proxy: %v", err)
	}
}

func (s *AppService) StartStreamApps() {
	apps, err := s.repo.ListAll()
	if err != nil {
		config.GetAppConfig().LogError("[AppService] Failed to list apps for stream startup: %v", err)
		return
	}

	for _, a := range apps {
		if a.IsStream() {
			if err := s.streamProxy.StartForApp(a); err != nil {
				config.GetAppConfig().LogError("[AppService] Failed to start stream for app=%s: %v", a.ID, err)
			}
		} else {
			s.healthChecker.Start(a)
		}
	}
}

func (s *AppService) resolveStreamPort(a *app.App) error {
	minPort := app.StreamPortMin()
	maxPort := app.StreamPortMax()

	if a.Config.ListenPort == 0 {
		port, err := s.findAvailablePort(a.ID, minPort, maxPort)
		if err != nil {
			return err
		}
		a.Config.ListenPort = port
		return nil
	}

	if err := s.checkPortConflict(a.ID, a.Config.ListenPort); err != nil {
		return err
	}
	return nil
}

func (s *AppService) findAvailablePort(excludeAppID string, minPort, maxPort int) (int, error) {
	apps, err := s.repo.ListAll()
	if err != nil {
		return 0, fmt.Errorf("failed to check port availability: %w", err)
	}

	used := make(map[int]bool)
	for _, existing := range apps {
		if existing.ID == excludeAppID {
			continue
		}
		if existing.IsStream() && existing.Config.ListenPort > 0 {
			used[existing.Config.ListenPort] = true
		}
	}

	for port := minPort; port <= maxPort; port++ {
		if !used[port] {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available port in range %d-%d", minPort, maxPort)
}

func (s *AppService) checkPortConflict(excludeAppID string, port int) error {
	apps, err := s.repo.ListAll()
	if err != nil {
		return fmt.Errorf("failed to check port conflict: %w", err)
	}

	for _, existing := range apps {
		if existing.ID == excludeAppID {
			continue
		}
		if existing.IsStream() && existing.Config.ListenPort == port {
			return fmt.Errorf("port %d is already used by app %s (%s)", port, existing.ID, existing.Domain)
		}
	}

	return nil
}
