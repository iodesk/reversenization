package service

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/vibeswaf/waf/internal/config"

	"github.com/vibeswaf/waf/internal/domain/rule"
	"github.com/vibeswaf/waf/internal/pipeline"
	"github.com/vibeswaf/waf/internal/repository"
)


type RuleService struct {
	repo      repository.RuleRepository
	engine    *rule.Engine
	cache     map[string][]*rule.CompiledRule
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
	lastCache map[string]time.Time
}


func NewRuleService(repo repository.RuleRepository, cacheTTL time.Duration) *RuleService {
	return &RuleService{
		repo:      repo,
		engine:    rule.NewEngine(),
		cache:     make(map[string][]*rule.CompiledRule),
		cacheTTL:  cacheTTL,
		lastCache: make(map[string]time.Time),
	}
}


func (s *RuleService) CreateRule(expressionRaw, name, scope, ruleGroup, action, description string, appID string, skipModules []string, priority int, enabled bool) (*rule.CompiledRule, error) {
	config.GetAppConfig().LogDebug("[RuleService] CreateRule called - name: %s, scope: %s, expression: %s", name, scope, expressionRaw)
	

	ast, err := s.engine.CompileExpression(expressionRaw)
	if err != nil {
		config.GetAppConfig().LogError("[RuleService] Failed to compile expression: %v", err)
		return nil, fmt.Errorf("invalid expression: %w", err)
	}
	
	config.GetAppConfig().LogDebug("[RuleService] Expression compiled successfully")


	compiledRule := &rule.CompiledRule{
		AppID:         appID,
		Name:          name,
		Scope:         scope,
		RuleGroup:     ruleGroup,
		ExpressionRaw: expressionRaw,
		AST:           ast,
		Action:        action,
		SkipModules:   skipModules,
		Priority:      priority,
		Enabled:       enabled,
		Description:   description,
	}


	config.GetAppConfig().LogDebug("[RuleService] Saving rule to repository...")
	if err := s.repo.Create(compiledRule); err != nil {
		config.GetAppConfig().LogError("[RuleService] Failed to save rule: %v", err)
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}
	
	config.GetAppConfig().LogDebug("[RuleService] Rule saved successfully with ID: %d", compiledRule.ID)


	s.InvalidateCache(appID)

	config.GetAppConfig().LogInfo("[RuleService] Created rule: %s (ID: %d)", name, compiledRule.ID)
	return compiledRule, nil
}


func (s *RuleService) UpdateRule(id int, expressionRaw, name, scope, ruleGroup, action, description string, appID string, skipModules []string, priority int, enabled bool) (*rule.CompiledRule, error) {

	ast, err := s.engine.CompileExpression(expressionRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid expression: %w", err)
	}


	compiledRule := &rule.CompiledRule{
		ID:            id,
		AppID:         appID,
		Name:          name,
		Scope:         scope,
		RuleGroup:     ruleGroup,
		ExpressionRaw: expressionRaw,
		AST:           ast,
		Action:        action,
		SkipModules:   skipModules,
		Priority:      priority,
		Enabled:       enabled,
		Description:   description,
	}


	if err := s.repo.Update(compiledRule); err != nil {
		return nil, fmt.Errorf("failed to update rule: %w", err)
	}


	s.InvalidateCache(appID)

	config.GetAppConfig().LogInfo("[RuleService] Updated rule: %s (ID: %d)", name, id)
	return compiledRule, nil
}


func (s *RuleService) DeleteRule(id int) error {

	existingRule, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("failed to get rule: %w", err)
	}


	if err := s.repo.Delete(id); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}


	s.InvalidateCache(existingRule.AppID)

	config.GetAppConfig().LogInfo("[RuleService] Deleted rule ID: %d", id)
	return nil
}


func (s *RuleService) GetRule(id int) (*rule.CompiledRule, error) {
	return s.repo.GetByID(id)
}


func (s *RuleService) ListRules() ([]*rule.CompiledRule, error) {
	return s.repo.ListAll()
}

func (s *RuleService) ListRulesByApp(appID string) ([]*rule.CompiledRule, error) {
	return s.repo.ListByScopeAll("app", appID)
}


func (s *RuleService) LoadMergedRules(appID string) ([]*rule.CompiledRule, error) {

	cacheKey := "merged:" + appID
	s.cacheMu.RLock()
	cached, exists := s.cache[cacheKey]
	lastCache, hasCache := s.lastCache[cacheKey]
	s.cacheMu.RUnlock()

	if exists && hasCache && time.Since(lastCache) < s.cacheTTL {
		return cached, nil
	}


	managedRules, err := s.repo.ListByScope("managed", "")
	if err != nil {
		return nil, fmt.Errorf("failed to load managed rules: %w", err)
	}

	appRules, err := s.repo.ListByScope("app", appID)
	if err != nil {
		return nil, fmt.Errorf("failed to load app rules: %w", err)
	}

	merged := append(managedRules, appRules...)

	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Priority < merged[j].Priority
	})

	s.cacheMu.Lock()
	s.cache[cacheKey] = merged
	s.lastCache[cacheKey] = time.Now()
	s.cacheMu.Unlock()

	config.GetAppConfig().LogDebug("[RuleService] Loaded %d rules for app %s (managed: %d, app: %d)",
		len(merged), appID, len(managedRules), len(appRules))

	return merged, nil
}


func (s *RuleService) ValidateExpression(expression string) error {
	return s.engine.ValidateExpression(expression)
}


func (s *RuleService) InvalidateCache(appID string) {
	// Global and managed rules (appID="") affect all apps — wipe entire cache.
	if appID == "" {
		s.InvalidateAllCache()
		return
	}
	cacheKey := "merged:" + appID
	s.cacheMu.Lock()
	delete(s.cache, cacheKey)
	delete(s.lastCache, cacheKey)
	s.cacheMu.Unlock()
	config.GetAppConfig().LogDebug("[RuleService] Cache invalidated for app: %s", appID)
}


func (s *RuleService) InvalidateAllCache() {
	s.cacheMu.Lock()
	s.cache = make(map[string][]*rule.CompiledRule)
	s.lastCache = make(map[string]time.Time)
	s.cacheMu.Unlock()
	config.GetAppConfig().LogDebug("[RuleService] All cache invalidated")
}


func ComputeHash(expression string) string {
	hash := sha256.Sum256([]byte(expression))
	return fmt.Sprintf("%x", hash)
}


func SerializeAST(ast *rule.Node) (string, error) {
	data, err := json.Marshal(ast)
	if err != nil {
		return "", err
	}
	return string(data), nil
}


func (s *RuleService) ReorderRules(ruleIDs []int) error {
	config.GetAppConfig().LogInfo("[RuleService] Reordering %d rules", len(ruleIDs))
	
	for i, id := range ruleIDs {

		r, err := s.repo.GetByID(id)
		if err != nil {
			config.GetAppConfig().LogError("[RuleService] Failed to get rule %d for reordering: %v", id, err)
			continue
		}


		r.Priority = (i + 1) * 10
		if err := s.repo.Update(r); err != nil {
			config.GetAppConfig().LogError("[RuleService] Failed to update priority for rule %d: %v", id, err)
			return err
		}
		

		s.InvalidateCache(r.AppID)
	}

	config.GetAppConfig().LogInfo("[RuleService] Successfully reordered %d rules", len(ruleIDs))
	return nil
}


func (s *RuleService) GetFieldMetadata() []rule.FieldMetadata {
	return s.engine.GetFieldMetadata()
}


func (s *RuleService) EvaluateRule(r *rule.CompiledRule, ctx *pipeline.Context) (bool, error) {
	reqCtx := &pipelineContextAdapter{ctx: ctx}
	return s.engine.Execute(r, reqCtx)
}
