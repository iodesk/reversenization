package repository

import (
	"database/sql"

	"github.com/vibeswaf/waf/internal/domain/app"
	"github.com/vibeswaf/waf/internal/domain/rule"
)


type RuleRepository interface {

	Create(rule *rule.CompiledRule) error
	Update(rule *rule.CompiledRule) error
	Delete(id int) error
	GetByID(id int) (*rule.CompiledRule, error)
	ListByScope(scope string, appID string) ([]*rule.CompiledRule, error)
	ListByScopeAll(scope string, appID string) ([]*rule.CompiledRule, error)
	ListAll() ([]*rule.CompiledRule, error)
	SaveAST(ruleID int, ast *rule.Node) error
}


type AppRepository interface {

	Create(app *app.App) error
	Update(app *app.App) error
	Delete(id string) error
	GetByID(id string) (*app.App, error)
	GetByDomain(domain string) (*app.App, error)
	ListAll() ([]*app.App, error)
	ToggleUnderAttackMode(appID string, enabled bool) error
}


type Repositories struct {
	Rule         RuleRepository
	App          AppRepository
	BotPattern   *BotPatternRepository
	BotIPRange   *BotIPRangeRepository
	Settings     *SettingsRepository
	IPAccess     IPAccessRepository
	User         *UserRepository
	Session      *SessionRepository
	Certificate  *CertificateRepository
	IPReputation *IPReputationRepository
}


func NewRepositories(db *sql.DB) *Repositories {
	return &Repositories{
		Rule:         NewRuleRepository(db),
		App:          NewAppRepository(db),
		BotPattern:   NewBotPatternRepository(db),
		BotIPRange:   NewBotIPRangeRepository(db),
		Settings:     NewSettingsRepository(db),
		IPAccess:     NewIPAccessRepository(db),
		User:         NewUserRepository(db),
		Session:      NewSessionRepository(db),
		Certificate:  NewCertificateRepository(db),
		IPReputation: NewIPReputationRepository(db),
	}
}
