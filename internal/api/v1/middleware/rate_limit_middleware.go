package middleware

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/ratelimit"
	"github.com/vibeswaf/waf/internal/service"
)

type RateLimitMiddleware struct {
	apiLimiter   *ratelimit.MemoryLimiter
	authLimiter  *ratelimit.MemoryLimiter
	loginLimiter *ratelimit.MemoryLimiter
	authService  *service.AuthService
}

func NewRateLimitMiddleware(authService *service.AuthService) *RateLimitMiddleware {
	apiLimit := envInt("API_RATE_LIMIT", 60)
	authLimit := envInt("API_RATE_LIMIT_AUTH", 120)
	apiWindow := envInt("API_RATE_WINDOW_SEC", 60)
	loginLimit := envInt("LOGIN_RATE_LIMIT", 5)
	loginWindow := envInt("LOGIN_RATE_WINDOW_SEC", 60)

	return &RateLimitMiddleware{
		apiLimiter:   ratelimit.NewMemory(apiLimit, time.Duration(apiWindow)*time.Second),
		authLimiter:  ratelimit.NewMemory(authLimit, time.Duration(apiWindow)*time.Second),
		loginLimiter: ratelimit.NewMemory(loginLimit, time.Duration(loginWindow)*time.Second),
		authService:  authService,
	}
}

func (m *RateLimitMiddleware) Limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)

		isLogin := r.URL.Path == "/api/v1/auth/login" && r.Method == http.MethodPost
		if isLogin {
			if !m.loginLimiter.Allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"Too many login attempts, try again later"}`))
				return
			}
		}

		limiter := m.apiLimiter
		if m.isAuthenticated(r) {
			limiter = m.authLimiter
		}

		if !limiter.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Too many requests, try again later"}`))
			return
		}

		next(w, r)
	}
}

func (m *RateLimitMiddleware) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	_, err = m.authService.ValidateSession(cookie.Value)
	return err == nil
}

func extractIP(r *http.Request) string {
	trustedStr := os.Getenv("TRUSTED_PROXIES")
	if trustedStr == "" {
		trustedStr = "127.0.0.1/32,::1/128"
	}
	trusted := make([]string, 0)
	for _, cidr := range strings.Split(trustedStr, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			trusted = append(trusted, cidr)
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return strings.TrimSpace(cfIP)
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}

	ips := strings.Split(xff, ",")
	if len(trusted) == 0 {
		return strings.TrimSpace(ips[0])
	}

	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		isTrusted := false
		for _, cidr := range trusted {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed != nil && network.Contains(parsed) {
				isTrusted = true
				break
			}
		}
		if !isTrusted {
			return ip
		}
	}
	return strings.TrimSpace(ips[0])
}
func envInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return n
}
