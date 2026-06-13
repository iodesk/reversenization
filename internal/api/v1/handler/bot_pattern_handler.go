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
	"github.com/vibeswaf/waf/internal/repository"
)

type BotPatternHandler struct {
	repo *repository.BotPatternRepository
}

func NewBotPatternHandler(repo *repository.BotPatternRepository) *BotPatternHandler {
	return &BotPatternHandler{repo: repo}
}

func (h *BotPatternHandler) List(w http.ResponseWriter, r *http.Request) {
	patterns, err := h.repo.GetAllPatterns()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch bot patterns")
		return
	}

	response := make([]dto.BotPatternResponse, len(patterns))
	for i, p := range patterns {
		response[i] = dto.BotPatternResponse{
			ID:          p.ID,
			PatternType: p.PatternType,
			Pattern:     p.Pattern,
			Score:       p.Score,
			VerifyIP:    p.VerifyIP,
			Enabled:     p.Enabled,
			Description: p.Description,
			CreatedAt:   p.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   p.UpdatedAt.Format(time.RFC3339),
		}
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *BotPatternHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateBotPatternRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}


	if req.PatternType == "" || req.Pattern == "" {
		respondError(w, http.StatusBadRequest, "PatternType and Pattern are required")
		return
	}


	if req.PatternType == "good_bot" {
		if req.Score > 0 {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid score for good_bot: %d. Must be 0 or negative (e.g., -100)", req.Score))
			return
		}
	} else {
		if req.Score < 0 || req.Score > 50 {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid score for %s: %d. Must be between 0-50", req.PatternType, req.Score))
			return
		}
	}

	pattern := &model.BotPattern{
		PatternType: req.PatternType,
		Pattern:     req.Pattern,
		Score:       req.Score,
		VerifyIP:    req.VerifyIP,
		Enabled:     req.Enabled,
		Description: req.Description,
	}

	if err := h.repo.AddPattern(pattern); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create bot pattern")
		return
	}

	resp := dto.BotPatternResponse{
		ID:          pattern.ID,
		PatternType: pattern.PatternType,
		Pattern:     pattern.Pattern,
		Score:       pattern.Score,
		VerifyIP:    pattern.VerifyIP,
		Enabled:     pattern.Enabled,
		Description: pattern.Description,
		CreatedAt:   pattern.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   pattern.UpdatedAt.Format(time.RFC3339),
	}

	respondJSON(w, http.StatusCreated, resp)
}

func (h *BotPatternHandler) Update(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid URL")
		return
	}
	idStr := parts[4]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	var req dto.UpdateBotPatternRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.PatternType == "" || req.Pattern == "" {
		respondError(w, http.StatusBadRequest, "PatternType and Pattern are required")
		return
	}


	if req.PatternType == "good_bot" {
		if req.Score > 0 {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid score for good_bot: %d. Must be 0 or negative (e.g., -100)", req.Score))
			return
		}
	} else {
		if req.Score < 0 || req.Score > 50 {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid score for %s: %d. Must be between 0-50", req.PatternType, req.Score))
			return
		}
	}

	pattern := &model.BotPattern{
		ID:          id,
		PatternType: req.PatternType,
		Pattern:     req.Pattern,
		Score:       req.Score,
		VerifyIP:    req.VerifyIP,
		Enabled:     req.Enabled,
		Description: req.Description,
	}

	if err := h.repo.UpdatePattern(pattern); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update bot pattern")
		return
	}

	resp := dto.BotPatternResponse{
		ID:          pattern.ID,
		PatternType: pattern.PatternType,
		Pattern:     pattern.Pattern,
		Score:       pattern.Score,
		VerifyIP:    pattern.VerifyIP,
		Enabled:     pattern.Enabled,
		Description: pattern.Description,
		UpdatedAt:   time.Now().Format(time.RFC3339),
	}

	respondJSON(w, http.StatusOK, resp)
}

func (h *BotPatternHandler) Delete(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid URL")
		return
	}
	idStr := parts[4]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	if err := h.repo.DeletePattern(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete bot pattern")
		return
	}

	respondJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *BotPatternHandler) BulkDelete(w http.ResponseWriter, r *http.Request) {
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
	if len(req.IDs) > 500 {
		respondError(w, http.StatusBadRequest, "Maximum 500 patterns per bulk delete")
		return
	}

	deleted, err := h.repo.BulkDeletePatterns(req.IDs)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to bulk delete bot patterns")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"deleted": deleted,
		"message": fmt.Sprintf("%d patterns deleted", deleted),
	})
}
