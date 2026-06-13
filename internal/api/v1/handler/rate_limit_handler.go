package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vibeswaf/waf/internal/api/v1/dto"
	"github.com/vibeswaf/waf/internal/logger"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/service"
)


type RateLimitHandler struct {
	repo             *repository.SettingsRepository
	rateLimitService *service.RateLimitService
	logger           *logger.Clickhouse
}

func NewRateLimitHandler(repo *repository.SettingsRepository, rateLimitService *service.RateLimitService, logger *logger.Clickhouse) *RateLimitHandler {
	return &RateLimitHandler{
		repo:             repo,
		rateLimitService: rateLimitService,
		logger:           logger,
	}
}


func (h *RateLimitHandler) GetRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	config, err := h.repo.GetRateLimitConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load rate limit config")
		return
	}


	response := dto.RateLimitResponse{
		Basic:  convertProfileToDTO(config.Basic),
		Attack: convertProfileToDTO(config.Attack),
		Error:  convertProfileToDTO(config.Error),
	}

	respondJSON(w, http.StatusOK, response)
}


func (h *RateLimitHandler) UpdateRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	var req dto.RateLimitUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	config, err := h.repo.GetRateLimitConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load current config")
		return
	}


	if req.Basic != nil {
		config.Basic = convertProfileFromDTO(*req.Basic)
	}
	if req.Attack != nil {
		config.Attack = convertProfileFromDTO(*req.Attack)
	}
	if req.Error != nil {
		config.Error = convertProfileFromDTO(*req.Error)
	}


	if err := h.repo.UpdateRateLimitConfig(config); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to save rate limit config")
		return
	}

	if h.rateLimitService != nil {
		h.rateLimitService.InvalidateCache("")
	}


	response := dto.RateLimitResponse{
		Basic:  convertProfileToDTO(config.Basic),
		Attack: convertProfileToDTO(config.Attack),
		Error:  convertProfileToDTO(config.Error),
	}

	respondJSON(w, http.StatusOK, response)
}


func convertProfileToDTO(profile model.RateLimitProfile) dto.RateLimitConfig {
	return dto.RateLimitConfig{
		Enabled:      profile.Enabled,
		Duration:     profile.Duration,
		Count:        profile.Count,
		Action:       profile.Action,
		ChallengeSec: profile.ChallengeSec,
	}
}

func convertProfileFromDTO(dto dto.RateLimitConfig) model.RateLimitProfile {
	return model.RateLimitProfile{
		Enabled:      dto.Enabled,
		Duration:     dto.Duration,
		Count:        dto.Count,
		Action:       dto.Action,
		ChallengeSec: dto.ChallengeSec,
	}
}

func (h *RateLimitHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondJSON(w, http.StatusOK, map[string]int64{"basic": 0, "attack": 0, "error": 0})
		return
	}

	query := `SELECT
		countIf(reason = 'rate_limit_exceeded' OR reason = 'basic_access_limit' OR reason = 'flood_penalty_active') as basic,
		countIf(reason = 'attack_flood_exceeded') as attack,
		countIf(reason = 'error_flood_exceeded') as error
	FROM waf_events
	WHERE ts >= now() - toIntervalDay(30)
		AND action IN ('block', 'challenge')`

	var basic, attack, errCount uint64
	row := h.logger.Conn().QueryRow(context.Background(), query)
	if err := row.Scan(&basic, &attack, &errCount); err != nil {
		respondJSON(w, http.StatusOK, map[string]int64{"basic": 0, "attack": 0, "error": 0})
		return
	}

	respondJSON(w, http.StatusOK, map[string]uint64{
		"basic":  basic,
		"attack": attack,
		"error":  errCount,
	})
}
