package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/domain/app"
)

type HealthCheckService struct {
	appService *AppService
	mu         sync.Mutex
	cancels    map[string]context.CancelFunc
	client     *http.Client
}

func NewHealthCheckService(appService *AppService) *HealthCheckService {
	return &HealthCheckService{
		appService: appService,
		cancels:    make(map[string]context.CancelFunc),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (s *HealthCheckService) Start(a *app.App) {
	if !a.Config.HealthCheck.Enabled {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if cancel, ok := s.cancels[a.ID]; ok {
		cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancels[a.ID] = cancel

	go s.run(ctx, a)
}

func (s *HealthCheckService) Stop(appID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel, ok := s.cancels[appID]; ok {
		cancel()
		delete(s.cancels, appID)
	}
}

func (s *HealthCheckService) run(ctx context.Context, a *app.App) {
	hc := a.Config.HealthCheck
	interval := time.Duration(hc.Interval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	failCounts := make(map[string]int)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := s.appService.GetApp(a.ID)
			if err != nil {
				continue
			}
			if !current.Config.HealthCheck.Enabled {
				return
			}

			changed := false
			for i, u := range current.Config.Upstreams {
				if !u.Enabled {
					continue
				}
				key := fmt.Sprintf("%s://%s:%d", u.Scheme, u.Host, u.Port)
				url := fmt.Sprintf("%s://%s:%d%s", u.Scheme, u.Host, u.Port, current.Config.HealthCheck.Path)

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					failCounts[key]++
				} else {
					resp, err := s.client.Do(req)
					if err != nil || resp.StatusCode >= 500 {
						failCounts[key]++
					} else {
						failCounts[key] = 0
					}
					if resp != nil {
						resp.Body.Close()
					}
				}

				wasHealthy := current.Config.Upstreams[i].Healthy
				isHealthy := failCounts[key] < current.Config.HealthCheck.Threshold
				if wasHealthy != isHealthy {
					current.Config.Upstreams[i].Healthy = isHealthy
					changed = true
					if isHealthy {
						config.GetAppConfig().LogInfo("[HealthCheck] Upstream %s recovered for app %s", key, a.ID)
					} else {
						config.GetAppConfig().LogWarn("[HealthCheck] Upstream %s marked unhealthy for app %s", key, a.ID)
					}
				}
			}

			if changed {
				_ = s.appService.repo.Update(current)
			}
		}
	}
}
