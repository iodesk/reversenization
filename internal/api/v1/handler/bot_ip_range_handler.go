package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
	"github.com/vibeswaf/waf/internal/service"
)

type BotIPRangeHandler struct {
	repo    *repository.BotIPRangeRepository
	fetcher *service.BotIPRangeFetcher
}

func NewBotIPRangeHandler(repo *repository.BotIPRangeRepository, fetcher *service.BotIPRangeFetcher) *BotIPRangeHandler {
	return &BotIPRangeHandler{repo: repo, fetcher: fetcher}
}

type botIPRangeResponse struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	SourceType  string     `json:"source_type"`
	URL         string     `json:"url"`
	IPRanges    []string   `json:"ip_ranges"`
	Enabled     bool       `json:"enabled"`
	Description string     `json:"description"`
	LastFetched *time.Time `json:"last_fetched"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at"`
}

type createBotIPRangeRequest struct {
	Name        string   `json:"name"`
	SourceType  string   `json:"source_type"`
	URL         string   `json:"url"`
	IPRanges    []string `json:"ip_ranges"`
	Enabled     bool     `json:"enabled"`
	Description string   `json:"description"`
}

func (h *BotIPRangeHandler) List(w http.ResponseWriter, r *http.Request) {
	ranges, err := h.repo.GetAll()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch bot IP ranges")
		return
	}

	response := make([]botIPRangeResponse, len(ranges))
	for i, item := range ranges {
		response[i] = toBotIPRangeResponse(item)
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *BotIPRangeHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createBotIPRangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	if req.SourceType != "json_url" && req.SourceType != "manual" {
		respondError(w, http.StatusBadRequest, "Source type must be 'json_url' or 'manual'")
		return
	}

	if req.SourceType == "json_url" && req.URL == "" {
		respondError(w, http.StatusBadRequest, "URL is required for json_url source type")
		return
	}

	if req.SourceType == "manual" && len(req.IPRanges) == 0 {
		respondError(w, http.StatusBadRequest, "At least one IP range is required for manual source type")
		return
	}

	if req.IPRanges == nil {
		req.IPRanges = []string{}
	}

	item := &model.BotIPRange{
		Name:        req.Name,
		SourceType:  req.SourceType,
		URL:         req.URL,
		IPRanges:    req.IPRanges,
		Enabled:     req.Enabled,
		Description: req.Description,
	}

	if err := h.repo.Create(item); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create bot IP range")
		return
	}

	if item.SourceType == "json_url" && item.URL != "" {
		go h.fetcher.FetchSingle(item.ID, item.URL)
	}

	respondJSON(w, http.StatusCreated, toBotIPRangeResponse(*item))
}

func (h *BotIPRangeHandler) Update(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}
	id, err := strconv.Atoi(parts[4])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	var req createBotIPRangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	if req.SourceType != "json_url" && req.SourceType != "manual" {
		respondError(w, http.StatusBadRequest, "Source type must be 'json_url' or 'manual'")
		return
	}

	if req.IPRanges == nil {
		req.IPRanges = []string{}
	}

	item := &model.BotIPRange{
		ID:          id,
		Name:        req.Name,
		SourceType:  req.SourceType,
		URL:         req.URL,
		IPRanges:    req.IPRanges,
		Enabled:     req.Enabled,
		Description: req.Description,
	}

	if err := h.repo.Update(item); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update bot IP range")
		return
	}

	respondJSON(w, http.StatusOK, toBotIPRangeResponse(*item))
}

func (h *BotIPRangeHandler) Delete(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}
	id, err := strconv.Atoi(parts[4])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	if err := h.repo.Delete(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete bot IP range")
		return
	}

	respondJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (h *BotIPRangeHandler) Sync(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}
	id, err := strconv.Atoi(parts[4])
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID")
		return
	}

	ranges, err := h.repo.GetAll()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch bot IP ranges")
		return
	}

	var target *model.BotIPRange
	for i := range ranges {
		if ranges[i].ID == id {
			target = &ranges[i]
			break
		}
	}

	if target == nil {
		respondError(w, http.StatusNotFound, "Bot IP range not found")
		return
	}

	if target.SourceType != "json_url" {
		respondError(w, http.StatusBadRequest, "Only json_url sources can be synced")
		return
	}

	ipRanges, err := h.fetcher.FetchFromURL(target.URL)
	if err != nil {
		respondError(w, http.StatusBadGateway, "Failed to fetch IP ranges: "+err.Error())
		return
	}

	if err := h.repo.UpdateIPRanges(id, ipRanges); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update IP ranges")
		return
	}

	now := time.Now()
	target.IPRanges = ipRanges
	target.LastFetched = &now

	respondJSON(w, http.StatusOK, toBotIPRangeResponse(*target))
}

func toBotIPRangeResponse(item model.BotIPRange) botIPRangeResponse {
	return botIPRangeResponse{
		ID:          item.ID,
		Name:        item.Name,
		SourceType:  item.SourceType,
		URL:         item.URL,
		IPRanges:    item.IPRanges,
		Enabled:     item.Enabled,
		Description: item.Description,
		LastFetched: item.LastFetched,
		CreatedAt:   item.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   item.UpdatedAt.Format(time.RFC3339),
	}
}
