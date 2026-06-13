package handler

import (
	"encoding/json"
	"net/http"

	appcfg "github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/service"
)

type SettingsHandler struct {
	repo             *repository.SettingsRepository
	wafService       *service.WAFService
	rateLimitService *service.RateLimitService
	settingsCache    *service.SettingsCache
}

func NewSettingsHandler(repo *repository.SettingsRepository, wafService *service.WAFService, rateLimitService *service.RateLimitService, settingsCache *service.SettingsCache) *SettingsHandler {
	return &SettingsHandler{
		repo:             repo,
		wafService:       wafService,
		rateLimitService: rateLimitService,
		settingsCache:    settingsCache,
	}
}

func (h *SettingsHandler) GetBotConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.repo.GetBotConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch bot configuration")
		return
	}

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) UpdateBotConfig(w http.ResponseWriter, r *http.Request) {
	var config model.BotConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	if err := ValidateBotConfig(config); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.repo.UpdateBotConfig(config); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update bot configuration")
		return
	}

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) GetWAFConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.repo.GetWAFConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch WAF configuration")
		return
	}

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) UpdateWAFConfig(w http.ResponseWriter, r *http.Request) {
	var config model.WAFConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	if err := ValidateWAFConfig(config); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.repo.UpdateWAFConfig(config); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update WAF configuration")
		return
	}

	// Trigger reload WAF config without restart
	if h.wafService != nil {
		if err := h.wafService.ReloadWAFConfig(config.ParanoiaLevel, config.AnomalyThreshold, config.OutboundAnomalyThreshold, config.AllowedMethods, config.DisabledRules, config.CustomRules); err != nil {
			appcfg.GetAppConfig().LogError("[SETTINGS] Failed to reload WAF config: %v", err)
			// Don't return error, config saved successfully
		} else {
			appcfg.GetAppConfig().LogInfo("[SETTINGS] WAF config reloaded: PL=%d, Inbound Threshold=%d, Outbound Threshold=%d", config.ParanoiaLevel, config.AnomalyThreshold, config.OutboundAnomalyThreshold)
		}
	}

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) GetScoringConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.repo.GetScoringConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch scoring configuration")
		return
	}

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) UpdateScoringConfig(w http.ResponseWriter, r *http.Request) {
	var config model.ScoringConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := ValidateScoringConfig(config); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.repo.UpdateScoringConfig(config); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update scoring configuration")
		return
	}

	h.settingsCache.Invalidate()

	appcfg.GetAppConfig().LogInfo("[SETTINGS] Scoring config updated: block=%d challenge=%d",
		config.Thresholds.Block, config.Thresholds.Challenge)

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) GetProtocolAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.repo.GetProtocolAnomalyConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch protocol anomaly configuration")
		return
	}

	respondJSON(w, http.StatusOK, config)
}

func (h *SettingsHandler) UpdateProtocolAnomalyConfig(w http.ResponseWriter, r *http.Request) {
	var config model.ProtocolAnomalyConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if config.Rules == nil {
		respondError(w, http.StatusBadRequest, "Rules map is required")
		return
	}

	if err := h.repo.UpdateProtocolAnomalyConfig(config); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update protocol anomaly configuration")
		return
	}

	appcfg.GetAppConfig().LogInfo("[SETTINGS] Protocol anomaly config updated: %d rules", len(config.Rules))

	respondJSON(w, http.StatusOK, config)
}
