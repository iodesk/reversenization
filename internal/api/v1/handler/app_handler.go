package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vibeswaf/waf/internal/api/v1/dto"
	"github.com/vibeswaf/waf/internal/domain/app"
	"github.com/vibeswaf/waf/internal/service"
)


type AppHandler struct {
	appService       *service.AppService
	rateLimitService *service.RateLimitService
}

func NewAppHandler(appService *service.AppService, rateLimitService *service.RateLimitService) *AppHandler {
	return &AppHandler{
		appService:       appService,
		rateLimitService: rateLimitService,
	}
}


func (h *AppHandler) CreateApp(w http.ResponseWriter, r *http.Request) {
	var req dto.AppCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	a := &app.App{
		ID:          req.ID,
		Domain:      req.Domain,
		Description: req.Description,
		Config:      req.Config,
	}


	if err := h.appService.CreateApp(a); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}


	resp := toAppResponse(a)
	respondJSON(w, http.StatusCreated, resp)
}


func (h *AppHandler) UpdateApp(w http.ResponseWriter, r *http.Request) {

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/apps/")

	var req dto.AppUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	a := &app.App{
		ID:          id,
		Domain:      req.Domain,
		Description: req.Description,
		Config:      req.Config,
	}


	if err := h.appService.UpdateApp(a); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if h.rateLimitService != nil {
		h.rateLimitService.InvalidateCache(id)
	}

	resp := toAppResponse(a)
	respondJSON(w, http.StatusOK, resp)
}


func (h *AppHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/apps/")


	if err := h.appService.DeleteApp(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "App deleted successfully",
	})
}


func (h *AppHandler) GetApp(w http.ResponseWriter, r *http.Request) {

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/apps/")


	a, err := h.appService.GetApp(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "App not found")
		return
	}


	resp := toAppResponse(a)
	respondJSON(w, http.StatusOK, resp)
}


func (h *AppHandler) ListApps(w http.ResponseWriter, r *http.Request) {

	apps, err := h.appService.ListApps()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}


	resp := make([]dto.AppResponse, len(apps))
	for i, a := range apps {
		resp[i] = toAppResponse(a)
	}

	respondJSON(w, http.StatusOK, resp)
}



func toAppResponse(a *app.App) dto.AppResponse {
	return dto.AppResponse{
		ID:              a.ID,
		Domain:          a.Domain,
		Description:     a.Description,
		Config:          a.Config,
		UnderAttackMode: a.UnderAttackMode,
		CreatedAt:       a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       a.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}


func (h *AppHandler) ToggleUnderAttackMode(w http.ResponseWriter, r *http.Request) {

	id := strings.TrimPrefix(r.URL.Path, "/api/v1/apps/")
	id = strings.TrimSuffix(id, "/under-attack")
	
	var req struct {
		Enabled bool `json:"enabled"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	if err := h.appService.ToggleUnderAttackMode(id, req.Enabled); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	
	message := "Under Attack mode disabled"
	if req.Enabled {
		message = "Under Attack mode enabled"
	}
	
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"enabled": req.Enabled,
		"message": message,
	})
}
