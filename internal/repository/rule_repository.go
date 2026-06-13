package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/vibeswaf/waf/internal/domain/rule"
)


type ruleRepository struct {
	db *sql.DB
}


func NewRuleRepository(db *sql.DB) RuleRepository {
	return &ruleRepository{db: db}
}


func (r *ruleRepository) Create(rule *rule.CompiledRule) error {
	if rule.Scope == "global" {
		return fmt.Errorf("scope 'global' is not allowed")
	}

	astJSON, err := json.Marshal(rule.AST)
	if err != nil {
		return fmt.Errorf("failed to serialize AST: %w", err)
	}

	query := `
		INSERT INTO security_rules (
			app_id, name, scope, rule_group, expression_raw, expression_ast,
			action, skip_modules, priority, enabled, description, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING rule_id
	`

	err = r.db.QueryRow(
		query,
		toNullString(rule.AppID),
		rule.Name,
		rule.Scope,
		rule.RuleGroup,
		rule.ExpressionRaw,
		string(astJSON),
		rule.Action,
		pq.Array(rule.SkipModules),
		rule.Priority,
		rule.Enabled,
		rule.Description,
		time.Now(),
		time.Now(),
	).Scan(&rule.ID)

	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	return nil
}


func (r *ruleRepository) Update(rule *rule.CompiledRule) error {

	astJSON, err := json.Marshal(rule.AST)
	if err != nil {
		return fmt.Errorf("failed to serialize AST: %w", err)
	}

	query := `
		UPDATE security_rules SET
			name = $1, scope = $2, rule_group = $3, expression_raw = $4, expression_ast = $5,
			action = $6, skip_modules = $7, priority = $8, enabled = $9, description = $10,
			updated_at = $11
		WHERE rule_id = $12
	`

	result, err := r.db.Exec(
		query,
		rule.Name,
		rule.Scope,
		rule.RuleGroup,
		rule.ExpressionRaw,
		string(astJSON),
		rule.Action,
		pq.Array(rule.SkipModules),
		rule.Priority,
		rule.Enabled,
		rule.Description,
		time.Now(),
		rule.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("rule not found")
	}

	return nil
}


func (r *ruleRepository) Delete(id int) error {
	query := `DELETE FROM security_rules WHERE rule_id = $1`

	result, err := r.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("rule not found")
	}

	return nil
}


func (r *ruleRepository) GetByID(id int) (*rule.CompiledRule, error) {
	query := `
		SELECT
			rule_id, app_id, name, scope, rule_group, expression_raw, expression_ast,
			action, skip_modules, priority, enabled, description
		FROM security_rules
		WHERE rule_id = $1
	`

	var (
		appID         sql.NullString
		name          string
		scope         string
		ruleGroup     string
		expressionRaw string
		expressionAST sql.NullString
		action        string
		skipModules   []string
		priority      int
		enabled       bool
		description   string
	)

	err := r.db.QueryRow(query, id).Scan(
		&id, &appID, &name, &scope, &ruleGroup, &expressionRaw, &expressionAST,
		&action, pq.Array(&skipModules), &priority, &enabled, &description,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("rule not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}

	var ast rule.Node
	if expressionAST.Valid && expressionAST.String != "" {
		if err := json.Unmarshal([]byte(expressionAST.String), &ast); err != nil {
			return nil, fmt.Errorf("failed to deserialize AST: %w", err)
		}
	}

	return &rule.CompiledRule{
		ID:            id,
		AppID:         appID.String,
		Name:          name,
		Scope:         scope,
		RuleGroup:     ruleGroup,
		ExpressionRaw: expressionRaw,
		AST:           &ast,
		Action:        action,
		SkipModules:   skipModules,
		Priority:      priority,
		Enabled:       enabled,
		Description:   description,
	}, nil
}


func (r *ruleRepository) ListByScope(scope string, appID string) ([]*rule.CompiledRule, error) {
	var query string
	var args []interface{}

	if scope == "global" || scope == "managed" {
		query = `
			SELECT
				rule_id, name, scope, rule_group, expression_raw, expression_ast,
				action, skip_modules, priority, enabled, description
			FROM security_rules
			WHERE scope = $1 AND enabled = true
			ORDER BY priority ASC
		`
		args = []interface{}{scope}
	} else {
		query = `
			SELECT
				rule_id, app_id, name, scope, rule_group, expression_raw, expression_ast,
				action, skip_modules, priority, enabled, description
			FROM security_rules
			WHERE scope = 'app' AND app_id = $1 AND enabled = true
			ORDER BY priority ASC
		`
		args = []interface{}{appID}
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	rules := make([]*rule.CompiledRule, 0)

	for rows.Next() {
		var (
			id            int
			appIDVal      sql.NullString
			name          string
			scopeVal      string
			ruleGroup     string
			expressionRaw string
			expressionAST sql.NullString
			action        string
			skipModules   []string
			priority      int
			enabled       bool
			description   string
		)

		var scanArgs []interface{}
		if scope == "global" || scope == "managed" {
			scanArgs = []interface{}{
				&id, &name, &scopeVal, &ruleGroup, &expressionRaw, &expressionAST,
				&action, pq.Array(&skipModules), &priority, &enabled, &description,
			}
		} else {
			scanArgs = []interface{}{
				&id, &appIDVal, &name, &scopeVal, &ruleGroup, &expressionRaw, &expressionAST,
				&action, pq.Array(&skipModules), &priority, &enabled, &description,
			}
		}

		if err := rows.Scan(scanArgs...); err != nil {
			continue
		}

		var ast rule.Node
		if expressionAST.Valid && expressionAST.String != "" {
			if err := json.Unmarshal([]byte(expressionAST.String), &ast); err != nil {
				continue
			}
		}

		rules = append(rules, &rule.CompiledRule{
			ID:            id,
			AppID:         appIDVal.String,
			Name:          name,
			Scope:         scopeVal,
			RuleGroup:     ruleGroup,
			ExpressionRaw: expressionRaw,
			AST:           &ast,
			Action:        action,
			SkipModules:   skipModules,
			Priority:      priority,
			Enabled:       enabled,
			Description:   description,
		})
	}

	return rules, nil
}

func (r *ruleRepository) ListByScopeAll(scope string, appID string) ([]*rule.CompiledRule, error) {
	query := `
		SELECT
			rule_id, app_id, name, scope, rule_group, expression_raw, expression_ast,
			action, skip_modules, priority, enabled, description
		FROM security_rules
		WHERE scope = 'app' AND app_id = $1
		ORDER BY priority ASC
	`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	rules := make([]*rule.CompiledRule, 0)

	for rows.Next() {
		var (
			id            int
			appIDVal      sql.NullString
			name          string
			scopeVal      string
			ruleGroup     string
			expressionRaw string
			expressionAST sql.NullString
			action        string
			skipModules   []string
			priority      int
			enabled       bool
			description   string
		)

		if err := rows.Scan(
			&id, &appIDVal, &name, &scopeVal, &ruleGroup, &expressionRaw, &expressionAST,
			&action, pq.Array(&skipModules), &priority, &enabled, &description,
		); err != nil {
			continue
		}

		var ast rule.Node
		if expressionAST.Valid && expressionAST.String != "" {
			if err := json.Unmarshal([]byte(expressionAST.String), &ast); err != nil {
				continue
			}
		}

		rules = append(rules, &rule.CompiledRule{
			ID:            id,
			AppID:         appIDVal.String,
			Name:          name,
			Scope:         scopeVal,
			RuleGroup:     ruleGroup,
			ExpressionRaw: expressionRaw,
			AST:           &ast,
			Action:        action,
			SkipModules:   skipModules,
			Priority:      priority,
			Enabled:       enabled,
			Description:   description,
		})
	}

	return rules, nil
}


func (r *ruleRepository) ListAll() ([]*rule.CompiledRule, error) {
	query := `
		SELECT
			rule_id, app_id, name, scope, rule_group, expression_raw, expression_ast,
			action, skip_modules, priority, enabled, description
		FROM security_rules
		ORDER BY priority ASC
	`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	rules := make([]*rule.CompiledRule, 0)

	for rows.Next() {
		var (
			id            int
			appID         sql.NullString
			name          string
			scope         string
			ruleGroup     string
			expressionRaw string
			expressionAST sql.NullString
			action        string
			skipModules   []string
			priority      int
			enabled       bool
			description   string
		)

		if err := rows.Scan(
			&id, &appID, &name, &scope, &ruleGroup, &expressionRaw, &expressionAST,
			&action, pq.Array(&skipModules), &priority, &enabled, &description,
		); err != nil {
			continue
		}

		var ast rule.Node
		if expressionAST.Valid && expressionAST.String != "" {
			if err := json.Unmarshal([]byte(expressionAST.String), &ast); err != nil {
				continue
			}
		}

		rules = append(rules, &rule.CompiledRule{
			ID:            id,
			AppID:         appID.String,
			Name:          name,
			Scope:         scope,
			RuleGroup:     ruleGroup,
			ExpressionRaw: expressionRaw,
			AST:           &ast,
			Action:        action,
			SkipModules:   skipModules,
			Priority:      priority,
			Enabled:       enabled,
			Description:   description,
		})
	}

	return rules, nil
}


// SaveAST persists the compiled AST for a rule.
func (r *ruleRepository) SaveAST(ruleID int, ast *rule.Node) error {
	astJSON, err := json.Marshal(ast)
	if err != nil {
		return fmt.Errorf("failed to serialize AST: %w", err)
	}

	query := `UPDATE security_rules SET expression_ast = $1 WHERE rule_id = $2`
	_, err = r.db.Exec(query, string(astJSON), ruleID)
	if err != nil {
		return fmt.Errorf("failed to save AST: %w", err)
	}

	return nil
}


func toNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

