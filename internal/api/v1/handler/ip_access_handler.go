package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vibeswaf/waf/internal/api/v1/dto"
	"github.com/vibeswaf/waf/internal/domain/ip_access"
	"github.com/vibeswaf/waf/internal/service"
)

type IPAccessHandler struct {
	service *service.IPAccessService
}

func NewIPAccessHandler(service *service.IPAccessService) *IPAccessHandler {
	return &IPAccessHandler{
		service: service,
	}
}

func extractAppID(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/apps/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func extractIDFromIPAccessPath(path string) (int, error) {
	parts := strings.Split(path, "/ip-access-rules/")
	if len(parts) < 2 {
		return 0, strconv.ErrSyntax
	}
	idStr := strings.Split(parts[1], "/")[0]
	return strconv.Atoi(idStr)
}

func toIPAccessResponse(rule *ip_access.IPAccessRule) *dto.IPAccessRuleResponse {
	return &dto.IPAccessRuleResponse{
		ID:          rule.ID,
		AppID:       rule.AppID,
		IPRange:     rule.IPRange,
		Description: rule.Description,
		Action:      rule.Action,
		Enabled:     rule.Enabled,
		CreatedAt:   rule.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   rule.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (h *IPAccessHandler) List(w http.ResponseWriter, r *http.Request) {
	appID := extractAppID(r.URL.Path)
	if appID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "app_id is required"})
		return
	}

	rules, err := h.service.List(appID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to fetch IP access rules"})
		return
	}

	response := make([]*dto.IPAccessRuleResponse, len(rules))
	for i, rule := range rules {
		response[i] = toIPAccessResponse(rule)
	}

	respondJSON(w, http.StatusOK, dto.IPAccessRulesListResponse{Rules: response})
}

func (h *IPAccessHandler) Create(w http.ResponseWriter, r *http.Request) {
	appID := extractAppID(r.URL.Path)
	if appID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "app_id is required"})
		return
	}

	var req dto.IPAccessRuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	createReq := &ip_access.CreateRequest{
		AppID:       appID,
		IPRange:     req.IPRange,
		Description: req.Description,
		Action:      req.Action,
		Enabled:     req.Enabled,
	}

	rule, err := h.service.Create(createReq)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusCreated, toIPAccessResponse(rule))
}

func (h *IPAccessHandler) Update(w http.ResponseWriter, r *http.Request) {
	appID := extractAppID(r.URL.Path)
	if appID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "app_id is required"})
		return
	}

	id, err := extractIDFromIPAccessPath(r.URL.Path)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid rule ID"})
		return
	}

	var req dto.IPAccessRuleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	updateReq := &ip_access.UpdateRequest{
		IPRange:     req.IPRange,
		Description: req.Description,
		Action:      req.Action,
		Enabled:     req.Enabled,
	}

	rule, err := h.service.Update(appID, id, updateReq)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, toIPAccessResponse(rule))
}

func (h *IPAccessHandler) Delete(w http.ResponseWriter, r *http.Request) {
	appID := extractAppID(r.URL.Path)
	if appID == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "app_id is required"})
		return
	}

	id, err := extractIDFromIPAccessPath(r.URL.Path)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid rule ID"})
		return
	}

	if err := h.service.Delete(appID, id); err != nil {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "IP access rule deleted successfully",
	})
}
