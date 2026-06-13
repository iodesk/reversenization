package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/api/v1/dto"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/service"
)

type IPReputationHandler struct {
	service *service.IPReputationService
	maxmind *service.MaxMindService
}

func NewIPReputationHandler(svc *service.IPReputationService, maxmind *service.MaxMindService) *IPReputationHandler {
	return &IPReputationHandler{service: svc, maxmind: maxmind}
}

func (h *IPReputationHandler) List(w http.ResponseWriter, r *http.Request) {
	entries, err := h.service.List()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch IP reputation entries")
		return
	}

	response := make([]dto.IPReputationEntryResponse, len(entries))
	for i, e := range entries {
		response[i] = dto.IPReputationEntryResponse{
			ID:          e.ID,
			EntryType:   e.EntryType,
			Value:       e.Value,
			Score:       e.Score,
			Category:    e.Category,
			Description: e.Description,
			Enabled:     e.Enabled,
			CreatedAt:   e.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   e.UpdatedAt.Format(time.RFC3339),
		}
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *IPReputationHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateIPReputationEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Support batch: if values array provided, create multiple entries
	values := req.Values
	if len(values) == 0 && req.Value != "" {
		values = []string{req.Value}
	}
	if len(values) == 0 {
		respondError(w, http.StatusBadRequest, "value or values is required")
		return
	}

	// Single entry: use Create (backward compat)
	if len(values) == 1 {
		val := strings.TrimSpace(values[0])
		desc := req.Description
		if req.AutoDetectProvider && h.maxmind != nil && desc == "" {
			desc = h.detectProvider(req.EntryType, val)
		}
		entry := &model.IPReputationEntry{
			EntryType:   req.EntryType,
			Value:       val,
			Score:       req.Score,
			Category:    req.Category,
			Description: desc,
			Enabled:     req.Enabled,
		}
		if err := h.service.Create(entry); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondJSON(w, http.StatusCreated, dto.IPReputationEntryResponse{
			ID:          entry.ID,
			EntryType:   entry.EntryType,
			Value:       entry.Value,
			Score:       entry.Score,
			Category:    entry.Category,
			Description: entry.Description,
			Enabled:     entry.Enabled,
			CreatedAt:   entry.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   entry.UpdatedAt.Format(time.RFC3339),
		})
		return
	}

	// Bulk: use BulkCreate (single Reload at end)
	entries := make([]*model.IPReputationEntry, 0, len(values))
	for _, val := range values {
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		desc := req.Description
		if req.AutoDetectProvider && h.maxmind != nil && desc == "" {
			desc = h.detectProvider(req.EntryType, val)
		}
		entries = append(entries, &model.IPReputationEntry{
			EntryType:   req.EntryType,
			Value:       val,
			Score:       req.Score,
			Category:    req.Category,
			Description: desc,
			Enabled:     req.Enabled,
		})
	}

	created, errs := h.service.BulkCreate(entries)

	if len(created) == 0 && len(errs) > 0 {
		respondError(w, http.StatusBadRequest, strings.Join(errs, "; "))
		return
	}

	createdResp := make([]dto.IPReputationEntryResponse, len(created))
	for i, e := range created {
		createdResp[i] = dto.IPReputationEntryResponse{
			ID:          e.ID,
			EntryType:   e.EntryType,
			Value:       e.Value,
			Score:       e.Score,
			Category:    e.Category,
			Description: e.Description,
			Enabled:     e.Enabled,
			CreatedAt:   e.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   e.UpdatedAt.Format(time.RFC3339),
		}
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"created": createdResp,
		"errors":  errs,
	})
}

func (h *IPReputationHandler) Update(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid URL")
		return
	}
	idStr := parts[len(parts)-1]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	var req dto.UpdateIPReputationEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	entry := &model.IPReputationEntry{
		ID:          id,
		EntryType:   req.EntryType,
		Value:       req.Value,
		Score:       req.Score,
		Category:    req.Category,
		Description: req.Description,
		Enabled:     req.Enabled,
	}

	if err := h.service.Update(entry); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp := dto.IPReputationEntryResponse{
		ID:          entry.ID,
		EntryType:   entry.EntryType,
		Value:       entry.Value,
		Score:       entry.Score,
		Category:    entry.Category,
		Description: entry.Description,
		Enabled:     entry.Enabled,
		UpdatedAt:   entry.UpdatedAt.Format(time.RFC3339),
	}

	respondJSON(w, http.StatusOK, resp)
}

func (h *IPReputationHandler) Delete(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid URL")
		return
	}
	idStr := parts[len(parts)-1]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	if err := h.service.Delete(id); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *IPReputationHandler) BulkDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []int `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if len(req.IDs) == 0 {
		respondError(w, http.StatusBadRequest, "ids is required")
		return
	}
	if len(req.IDs) > 5000 {
		respondError(w, http.StatusBadRequest, "Maximum 5000 entries per bulk delete")
		return
	}

	deleted, err := h.service.BulkDelete(req.IDs)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to bulk delete: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"message": fmt.Sprintf("%d entries deleted", deleted),
	})
}

func (h *IPReputationHandler) BulkUpdateScore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs   []int `json:"ids"`
		Score int   `json:"score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if len(req.IDs) == 0 {
		respondError(w, http.StatusBadRequest, "ids is required")
		return
	}
	if len(req.IDs) > 5000 {
		respondError(w, http.StatusBadRequest, "Maximum 5000 entries per bulk update")
		return
	}
	if req.Score < 1 || req.Score > 100 {
		respondError(w, http.StatusBadRequest, "score must be between 1 and 100")
		return
	}

	updated, err := h.service.BulkUpdateScore(req.IDs, req.Score)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to bulk update: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"updated": updated,
		"message": fmt.Sprintf("%d entries updated to score %d", updated, req.Score),
	})
}

func (h *IPReputationHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.service.GetConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch IP reputation config")
		return
	}

	respondJSON(w, http.StatusOK, dto.IPReputationConfigResponse{
		MaxmindDCScore:   cfg.MaxmindDCScore,
		MaxmindASNScore:  cfg.MaxmindASNScore,
		SpamhausIPScore:  cfg.SpamhausIPScore,
		SpamhausASNScore: cfg.SpamhausASNScore,
	})
}

func (h *IPReputationHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req dto.UpdateIPReputationConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.MaxmindDCScore < 0 || req.MaxmindDCScore > 100 {
		respondError(w, http.StatusBadRequest, "maxmind_dc_score must be between 0 and 100")
		return
	}
	if req.MaxmindASNScore < 0 || req.MaxmindASNScore > 100 {
		respondError(w, http.StatusBadRequest, "maxmind_asn_score must be between 0 and 100")
		return
	}
	if req.SpamhausIPScore < 0 || req.SpamhausIPScore > 100 {
		respondError(w, http.StatusBadRequest, "spamhaus_ip_score must be between 0 and 100")
		return
	}
	if req.SpamhausASNScore < 0 || req.SpamhausASNScore > 100 {
		respondError(w, http.StatusBadRequest, "spamhaus_asn_score must be between 0 and 100")
		return
	}

	cfg := model.IPReputationConfig{
		MaxmindDCScore:   req.MaxmindDCScore,
		MaxmindASNScore:  req.MaxmindASNScore,
		SpamhausIPScore:  req.SpamhausIPScore,
		SpamhausASNScore: req.SpamhausASNScore,
	}

	if err := h.service.UpdateConfig(cfg); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update IP reputation config")
		return
	}

	respondJSON(w, http.StatusOK, dto.IPReputationConfigResponse{
		MaxmindDCScore:   cfg.MaxmindDCScore,
		MaxmindASNScore:  cfg.MaxmindASNScore,
		SpamhausIPScore:  cfg.SpamhausIPScore,
		SpamhausASNScore: cfg.SpamhausASNScore,
	})
}

func (h *IPReputationHandler) SyncSpamhaus(w http.ResponseWriter, r *http.Request) {
	totalIPs, totalASNs, fetchErrors, err := h.service.SyncSpamhaus()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to sync Spamhaus: "+err.Error())
		return
	}

	msg := fmt.Sprintf("Synced %d IPs and %d ASNs from Spamhaus DROP lists", totalIPs, totalASNs)
	if len(fetchErrors) > 0 {
		msg += fmt.Sprintf(" (%d fetch errors)", len(fetchErrors))
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"total_ips":  totalIPs,
		"total_asns": totalASNs,
		"errors":     fetchErrors,
		"message":    msg,
	})
}

func (h *IPReputationHandler) detectProvider(entryType, value string) string {
	if entryType == "ip" {
		result, err := h.maxmind.Lookup(value)
		if err == nil && result.ASNOrg != "" {
			desc := result.ASNOrg
			if result.Country != "" {
				desc += " (" + result.Country + ")"
			}
			return desc
		}
	} else if entryType == "asn" {
		asn, err := strconv.ParseUint(value, 10, 32)
		if err == nil {
			org := h.maxmind.LookupASNOrg(uint(asn))
			if org != "" {
				return org
			}
		}
	}
	return ""
}
