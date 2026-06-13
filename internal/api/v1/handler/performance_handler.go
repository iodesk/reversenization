package handler

import (
	"encoding/json"
	"net/http"

	"github.com/vibeswaf/waf/internal/metrics"
)


type PerformanceHandler struct{}


func NewPerformanceHandler() *PerformanceHandler {
	return &PerformanceHandler{}
}


func (h *PerformanceHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := metrics.GetStats()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
