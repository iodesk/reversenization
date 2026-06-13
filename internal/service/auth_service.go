package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidSession     = errors.New("invalid or expired session")
)

const sessionTTL = 7 * 24 * time.Hour // 7 days

type Session struct {
	Token     string
	UserID    int
	Username  string
	ExpiresAt time.Time
}

type AuthService struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	bcryptCost  int
}

func NewAuthService(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository, bcryptCost int) *AuthService {
	svc := &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		bcryptCost:  bcryptCost,
	}

	go svc.cleanupLoop()

	return svc
}

func (s *AuthService) Login(username, password string) (*Session, *model.User, error) {
	user, err := s.userRepo.FindByUsernameOrEmail(username)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, nil, ErrInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	token := generateSessionToken()
	expiresAt := time.Now().Add(sessionTTL)

	if err := s.sessionRepo.Create(token, user.ID, expiresAt); err != nil {
		return nil, nil, err
	}

	_ = s.userRepo.UpdateLastLogin(user.ID)

	session := &Session{
		Token:     token,
		UserID:    user.ID,
		Username:  user.Username,
		ExpiresAt: expiresAt,
	}

	return session, user, nil
}

func (s *AuthService) Logout(token string) {
	_ = s.sessionRepo.Delete(token)
}

func (s *AuthService) ValidateSession(token string) (*Session, error) {
	row, err := s.sessionRepo.FindByToken(token)
	if err != nil {
		return nil, ErrInvalidSession
	}
	if row == nil {
		return nil, ErrInvalidSession
	}

	if time.Now().After(row.ExpiresAt) {
		_ = s.sessionRepo.Delete(token)
		return nil, ErrInvalidSession
	}

	user, err := s.userRepo.FindByID(row.UserID)
	if err != nil || user == nil {
		return nil, ErrInvalidSession
	}

	return &Session{
		Token:     row.Token,
		UserID:    row.UserID,
		Username:  user.Username,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

func (s *AuthService) GetUserBySession(token string) (*model.User, error) {
	session, err := s.ValidateSession(token)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.FindByID(session.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func (s *AuthService) ChangePassword(userID int, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		return ErrInvalidCredentials
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost)
	if err != nil {
		return err
	}

	return s.userRepo.UpdatePassword(userID, string(hashedPassword))
}

func (s *AuthService) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (s *AuthService) CreateUser(username, password, email, role string) (*model.User, error) {
	hashedPassword, err := s.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Username:     username,
		PasswordHash: hashedPassword,
		Email:        email,
		Role:         role,
		Enabled:      true,
	}

	err = s.userRepo.Create(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) NeedsSetup() (bool, error) {
	count, err := s.userRepo.Count()
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func (s *AuthService) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		deleted, err := s.sessionRepo.DeleteExpired()
		if err != nil {
			config.GetAppConfig().LogWarn("[Auth] Session cleanup error: %v", err)
			continue
		}
		if deleted > 0 {
			config.GetAppConfig().LogInfo("[Auth] Cleaned %d expired sessions", deleted)
		}
	}
}

func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
