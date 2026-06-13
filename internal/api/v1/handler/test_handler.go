package handler

import (
	"net/http"
	"strings"

	"github.com/vibeswaf/waf/internal/ratelimit"
)

type TestHandler struct {
	limiter *ratelimit.RateLimiter
}

func NewTestHandler() *TestHandler {
	return &TestHandler{
		limiter: ratelimit.NewRateLimiter(),
	}
}

func (h *TestHandler) TestRateLimit(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	} else {
		if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}
	}

	key := ratelimit.GenerateKey(clientIP, r.UserAgent())

	if h.limiter.Allow(key, 100, 10.0) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	} else {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("rate_limited"))
	}
}
