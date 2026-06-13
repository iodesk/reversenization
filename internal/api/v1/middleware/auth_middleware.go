package middleware

import (
	"net/http"
	"strconv"

	"github.com/vibeswaf/waf/internal/service"
)


type AuthMiddleware struct {
	authService *service.AuthService
}


func NewAuthMiddleware(authService *service.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}


func (m *AuthMiddleware) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, `{"error":"Unauthorized - No session cookie"}`, http.StatusUnauthorized)
			return
		}


		session, err := m.authService.ValidateSession(cookie.Value)
		if err != nil {
			http.Error(w, `{"error":"Unauthorized - Invalid or expired session"}`, http.StatusUnauthorized)
			return
		}


		r.Header.Set("X-User-ID", strconv.Itoa(session.UserID))
		r.Header.Set("X-Username", session.Username)


		next(w, r)
	}
}