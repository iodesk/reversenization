package handler

import (
	"encoding/json"
	"net/http"

	"github.com/vibeswaf/waf/internal/cache"
)

type CacheHandler struct {
	decisionCache *cache.DecisionCache
}

func NewCacheHandler(decisionCache *cache.DecisionCache) *CacheHandler {
	return &CacheHandler{decisionCache: decisionCache}
}

func (h *CacheHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.decisionCache.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
