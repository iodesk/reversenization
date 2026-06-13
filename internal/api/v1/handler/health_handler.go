package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/service"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"service": "VibesWAF",
		"version": config.Version,
		"status":  "ok",
	})
}

func (h *HealthHandler) HealthForApp(w http.ResponseWriter, r *http.Request, appService *service.AppService) {
	name := "default"
	if appService != nil {
		host := r.Host
		if i := strings.LastIndex(host, ":"); i != -1 {
			host = host[:i]
		}
		if a, err := appService.GetAppByDomain(host); err == nil && a != nil {
			name = a.ID
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"service": name,
		"status":  "ok",
	})
}