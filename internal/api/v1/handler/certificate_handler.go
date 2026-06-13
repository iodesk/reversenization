package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/vibeswaf/waf/internal/api/v1/dto"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/service"
)

type CertificateHandler struct {
	certService *service.CertificateService
}

func NewCertificateHandler(certService *service.CertificateService) *CertificateHandler {
	return &CertificateHandler{
		certService: certService,
	}
}

func (h *CertificateHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	appID := r.URL.Query().Get("app_id")
	
	config.GetAppConfig().LogDebug("[CertHandler] List certificates requested, app_id=%s", appID)

	var certs []*dto.CertificateResponse

	if appID != "" {
		infos, err := h.certService.ListByAppID(appID)
		if err != nil {
			config.GetAppConfig().LogError("[CertHandler] Failed to list by app_id: %v", err)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		certs = make([]*dto.CertificateResponse, len(infos))
		for i, info := range infos {
			certs[i] = toCertificateResponse(info)
		}
	} else {
		infos, err := h.certService.ListAll()
		if err != nil {
			config.GetAppConfig().LogError("[CertHandler] Failed to list all: %v", err)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		certs = make([]*dto.CertificateResponse, len(infos))
		for i, info := range infos {
			certs[i] = toCertificateResponse(info)
		}
	}

	config.GetAppConfig().LogDebug("[CertHandler] Returning %d certificates", len(certs))
	respondJSON(w, http.StatusOK, certs)
}

func (h *CertificateHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	domain := extractDomainFromPath(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Invalid domain")
		return
	}

	info, err := h.certService.GetByDomain(domain)
	if err != nil {
		respondError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	respondJSON(w, http.StatusOK, toCertificateResponse(info))
}

func (h *CertificateHandler) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	domain := extractDomainFromPath(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Invalid domain")
		return
	}

	config.GetAppConfig().LogInfo("[CertHandler] Manual renewal requested for %s", domain)

	if err := h.certService.RenewCertificate(domain); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Certificate renewal initiated",
	})
}

func (h *CertificateHandler) ValidateCertificate(w http.ResponseWriter, r *http.Request) {
	domain := extractDomainFromPath(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Invalid domain")
		return
	}

	config.GetAppConfig().LogInfo("[CertHandler] Validation requested for %s", domain)

	info, err := h.certService.ValidateCertificate(domain)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, toCertificateResponse(info))
}

func (h *CertificateHandler) ToggleAutoRenew(w http.ResponseWriter, r *http.Request) {
	domain := extractDomainFromPath(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Invalid domain")
		return
	}

	var req dto.ToggleAutoRenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.certService.ToggleAutoRenew(domain, req.Enabled); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	action := "disabled"
	if req.Enabled {
		action = "enabled"
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Auto-renew " + action,
	})
}

func (h *CertificateHandler) GetCertificateLogs(w http.ResponseWriter, r *http.Request) {
	domain := extractDomainFromPath(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Invalid domain")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	logs, err := h.certService.GetLogs(domain, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := make([]*dto.CertificateLogResponse, len(logs))
	for i, log := range logs {
		response[i] = &dto.CertificateLogResponse{
			ID:        log.ID,
			Domain:    log.Domain,
			Action:    log.Action,
			Status:    log.Status,
			Message:   log.Message,
			CreatedAt: log.CreatedAt,
		}
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *CertificateHandler) SyncFromFilesystem(w http.ResponseWriter, r *http.Request) {
	config.GetAppConfig().LogInfo("[CertHandler] Sync from filesystem requested")

	if err := h.certService.SyncAllFromFilesystem(); err != nil {
		config.GetAppConfig().LogError("[CertHandler] Sync failed: %v", err)
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	config.GetAppConfig().LogInfo("[CertHandler] Sync completed successfully")
	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Certificates synced from filesystem",
	})
}

func (h *CertificateHandler) DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	domain := extractDomainFromPath(r.URL.Path, "/api/v1/certificates/")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Invalid domain")
		return
	}

	config.GetAppConfig().LogInfo("[CertHandler] Delete requested for %s", domain)

	if err := h.certService.DeleteCertificate(domain); err != nil {
		config.GetAppConfig().LogError("[CertHandler] Delete failed: %v", err)
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Certificate deleted",
	})
}

func (h *CertificateHandler) BulkDeleteCertificates(w http.ResponseWriter, r *http.Request) {
	var req dto.BulkDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(req.Domains) == 0 {
		respondError(w, http.StatusBadRequest, "No domains provided")
		return
	}

	config.GetAppConfig().LogInfo("[CertHandler] Bulk delete requested for %d certificates", len(req.Domains))

	deleted, err := h.certService.BulkDeleteCertificates(req.Domains)
	if err != nil {
		config.GetAppConfig().LogError("[CertHandler] Bulk delete failed: %v", err)
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.BulkDeleteResponse{
		Success: true,
		Message: fmt.Sprintf("%d certificates deleted", deleted),
		Deleted: deleted,
	})
}

func extractDomainFromPath(path, prefix string) string {
	domain := strings.TrimPrefix(path, prefix)
	domain = strings.Split(domain, "/")[0]
	return domain
}

func toCertificateResponse(info *model.CertificateInfo) *dto.CertificateResponse {
	return &dto.CertificateResponse{
		Domain:          info.Domain,
		Status:          info.Status,
		Issuer:          info.Issuer,
		ExpiresAt:       info.ExpiresAt,
		DaysUntilExpiry: info.DaysUntilExpiry,
		AutoRenew:       info.AutoRenew,
		IsExpiringSoon:  info.IsExpiringSoon,
		LastRenewAt:     info.LastRenewAt,
		LastRenewStatus: info.LastRenewStatus,
	}
}
