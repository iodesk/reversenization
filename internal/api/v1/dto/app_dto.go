package dto

import "github.com/vibeswaf/waf/internal/domain/app"

type AppCreateRequest struct {
	ID          string        `json:"id"`
	Domain      string        `json:"domain"`
	Description string        `json:"description,omitempty"`
	Config      app.AppConfig `json:"config"`
}

type AppUpdateRequest struct {
	Domain      string        `json:"domain"`
	Description string        `json:"description,omitempty"`
	Config      app.AppConfig `json:"config"`
}

type AppResponse struct {
	ID              string        `json:"id"`
	Domain          string        `json:"domain"`
	Description     string        `json:"description,omitempty"`
	Config          app.AppConfig `json:"config"`
	UnderAttackMode bool          `json:"under_attack_mode"`
	CreatedAt       string        `json:"created_at"`
	UpdatedAt       string        `json:"updated_at"`
}
