package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/service"
)


type AuthHandler struct {
	authService *service.AuthService
}


func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}


func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}


	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"Username and password are required"}`, http.StatusBadRequest)
		return
	}


	session, user, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			http.Error(w, `{"error":"Invalid username or password"}`, http.StatusUnauthorized)
		} else {
			http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		}
		return
	}



	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})


	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.AuthResponse{
		User:    user,
		Message: "Login successful",
	})
}


func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")
	if err == nil {

		h.authService.Logout(cookie.Value)
	}


	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logout successful",
	})
}


func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}


	user, err := h.authService.GetUserBySession(cookie.Value)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}


	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}


func (h *AuthHandler) NeedsSetup(w http.ResponseWriter, r *http.Request) {
	needed, err := h.authService.NeedsSetup()
	if err != nil {
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"needs_setup": needed})
}

func (h *AuthHandler) Setup(w http.ResponseWriter, r *http.Request) {
	needed, err := h.authService.NeedsSetup()
	if err != nil {
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	if !needed {
		http.Error(w, `{"error":"Setup already completed"}`, http.StatusForbidden)
		return
	}

	var req model.SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" || req.Email == "" {
		http.Error(w, `{"error":"Username, password, and email are required"}`, http.StatusBadRequest)
		return
	}

	if len(req.Password) < 8 {
		http.Error(w, `{"error":"Password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	user, err := h.authService.CreateUser(req.Username, req.Password, req.Email, "admin")
	if err != nil {
		http.Error(w, `{"error":"Failed to create admin user"}`, http.StatusInternalServerError)
		return
	}

	if os.Getenv("SESSION_SECRET") == "" {
		secret := generateSecret(32)
		os.Setenv("SESSION_SECRET", secret)
		appendToEnvFile("SESSION_SECRET", secret)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.AuthResponse{
		User:    user,
		Message: "Setup completed successfully",
	})
}

func generateSecret(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var envFileMu sync.Mutex

func appendToEnvFile(key, value string) {
	envPath := ".env"

	envFileMu.Lock()
	defer envFileMu.Unlock()

	content, err := os.ReadFile(envPath)
	if err != nil {
		return
	}

	lines := strings.Split(string(content), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+"=") || strings.HasPrefix(trimmed, "#"+key+"=") {
			lines[i] = fmt.Sprintf("%s=%s", key, value)
			found = true
			break
		}
	}

	if !found {
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	_ = os.WriteFile(envPath, []byte(strings.Join(lines, "\n")), 0600)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}


	user, err := h.authService.GetUserBySession(cookie.Value)
	if err != nil {
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}


	var req model.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}


	if req.OldPassword == "" || req.NewPassword == "" {
		http.Error(w, `{"error":"Old password and new password are required"}`, http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 8 {
		http.Error(w, `{"error":"New password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}


	err = h.authService.ChangePassword(user.ID, req.OldPassword, req.NewPassword)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			http.Error(w, `{"error":"Invalid old password"}`, http.StatusUnauthorized)
		} else {
			http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password changed successfully",
	})
}