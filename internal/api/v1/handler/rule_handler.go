package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/vibeswaf/waf/internal/api/v1/dto"
	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/domain/rule"
	"github.com/vibeswaf/waf/internal/logger"
	"github.com/vibeswaf/waf/internal/service"
)



type RuleHandler struct {
	ruleService *service.RuleService
	logger      *logger.Clickhouse
}


func NewRuleHandler(ruleService *service.RuleService, logger *logger.Clickhouse) *RuleHandler {
	return &RuleHandler{
		ruleService: ruleService,
		logger:      logger,
	}
}


func (h *RuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	var req dto.RuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	if req.Name == "" || req.ExpressionRaw == "" || req.Action == "" {
		config.GetAppConfig().LogError("[RuleHandler] Validation failed - Name: %s, Expression: %s, Action: %s", req.Name, req.ExpressionRaw, req.Action)
		respondError(w, http.StatusBadRequest, "Missing required fields")
		return
	}
	
	config.GetAppConfig().LogInfo("[RuleHandler] Creating rule: %s", req.Name)


	compiledRule, err := h.ruleService.CreateRule(
		req.ExpressionRaw,
		req.Name,
		req.Scope,
		req.RuleGroup,
		req.Action,
		req.Description,
		req.AppID,
		req.SkipModules,
		req.Priority,
		req.Enabled,
	)

	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}


	resp := toRuleResponse(compiledRule)
	respondJSON(w, http.StatusCreated, resp)
}


func (h *RuleHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {

	id, err := extractIDFromPath(r.URL.Path, "/api/v1/rules/")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	var req dto.RuleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	compiledRule, err := h.ruleService.UpdateRule(
		id,
		req.ExpressionRaw,
		req.Name,
		req.Scope,
		req.RuleGroup,
		req.Action,
		req.Description,
		req.AppID,
		req.SkipModules,
		req.Priority,
		req.Enabled,
	)

	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}


	resp := toRuleResponse(compiledRule)
	respondJSON(w, http.StatusOK, resp)
}


func (h *RuleHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {

	id, err := extractIDFromPath(r.URL.Path, "/api/v1/rules/")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}


	if err := h.ruleService.DeleteRule(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Rule deleted successfully",
	})
}


func (h *RuleHandler) GetRule(w http.ResponseWriter, r *http.Request) {

	id, err := extractIDFromPath(r.URL.Path, "/api/v1/rules/")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}


	compiledRule, err := h.ruleService.GetRule(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Rule not found")
		return
	}


	resp := toRuleResponse(compiledRule)
	respondJSON(w, http.StatusOK, resp)
}


func (h *RuleHandler) ListRules(w http.ResponseWriter, r *http.Request) {

	rules, err := h.ruleService.ListRules()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}


	resp := make([]dto.RuleResponse, len(rules))
	for i, r := range rules {
		resp[i] = toRuleResponse(r)
	}

	respondJSON(w, http.StatusOK, resp)
}


func (h *RuleHandler) ValidateExpression(w http.ResponseWriter, r *http.Request) {
	var req dto.ValidateExpressionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}


	err := h.ruleService.ValidateExpression(req.Expression)

	resp := dto.ValidateExpressionResponse{
		Valid: err == nil,
	}

	if err != nil {
		resp.Error = err.Error()
	}

	respondJSON(w, http.StatusOK, resp)
}


func (h *RuleHandler) GetFieldMetadata(w http.ResponseWriter, r *http.Request) {
	fields := h.ruleService.GetFieldMetadata()
	

	dtoFields := make([]dto.FieldMetadata, len(fields))
	for i, f := range fields {
		dtoFields[i] = dto.FieldMetadata{
			Name:             f.Name,
			Type:             f.Type,
			AllowedOperators: getOperatorMetadata(f.AllowedOperators, f.Type),
			Description:      f.Description,
		}
	}
	
	respondJSON(w, http.StatusOK, dto.FieldMetadataResponse{
		Fields: dtoFields,
	})
}


func getOperatorMetadata(operators []string, fieldType string) []dto.OperatorMetadata {
	result := make([]dto.OperatorMetadata, len(operators))
	
	for i, op := range operators {
		result[i] = dto.OperatorMetadata{
			Value:       op,
			Label:       getOperatorLabel(op, fieldType),
			Symbol:      op,
			Description: getOperatorDescription(op, fieldType),
		}
	}
	
	return result
}


func getOperatorLabel(op, fieldType string) string {

	if fieldType == "bool" {
		switch op {
		case "eq":
			return "Is True"
		case "neq":
			return "Is False"
		}
	}
	

	switch op {
	case "eq":
		return "Equals"
	case "neq":
		return "Not Equals"
	case "in":
		return "In"
	case "not_in":
		return "Not In"
	case "contains":
		return "Contains"
	case "not_contains":
		return "Does Not Contain"
	case "prefix":
		return "Starts With"
	case "suffix":
		return "Ends With"
	case "regex":
		return "Match Regex"
	case "not_regex":
		return "Not Match Regex"
	case "gt":
		return "Greater Than"
	case "lt":
		return "Less Than"
	case "gte":
		return "Greater or Equal"
	case "lte":
		return "Less or Equal"
	case "exists":
		return "Exists"
	case "not_exists":
		return "Not Exists"
	default:
		return op
	}
}


func getOperatorDescription(op, fieldType string) string {
	if fieldType == "bool" {
		switch op {
		case "eq":
			return "Value is true"
		case "neq":
			return "Value is false"
		}
	}
	
	switch op {
	case "eq":
		return "Exact match"
	case "neq":
		return "Does not match"
	case "in":
		return "Value in list"
	case "not_in":
		return "Value not in list"
	case "contains":
		return "Contains substring"
	case "not_contains":
		return "Does not contain"
	case "prefix":
		return "Starts with string"
	case "suffix":
		return "Ends with string"
	case "regex":
		return "Regex pattern match"
	case "not_regex":
		return "Does not match regex"
	case "gt":
		return "Greater than"
	case "lt":
		return "Less than"
	case "gte":
		return "Greater than or equal"
	case "lte":
		return "Less than or equal"
	case "exists":
		return "Field exists"
	case "not_exists":
		return "Field does not exist"
	default:
		return ""
	}
}



func toRuleResponse(r *rule.CompiledRule) dto.RuleResponse {
	return dto.RuleResponse{
		ID:                  r.ID,
		AppID:               r.AppID,
		Name:                r.Name,
		Scope:               r.Scope,
		RuleGroup:           r.RuleGroup,
		ExpressionRaw:       r.ExpressionRaw,
		ExpressionStructure: r.AST,
		Action:              r.Action,
		SkipModules:         r.SkipModules,
		Priority:            r.Priority,
		Enabled:             r.Enabled,
		Description:         r.Description,
	}
}

func extractIDFromPath(path, prefix string) (int, error) {
	idStr := strings.TrimPrefix(path, prefix)
	return strconv.Atoi(idStr)
}

func extractAppIDFromRulePath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/apps/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func extractIDFromRuleAppPath(path string) (int, error) {
	parts := strings.Split(path, "/rules/")
	if len(parts) < 2 {
		return 0, strconv.ErrSyntax
	}
	idStr := strings.Split(parts[1], "/")[0]
	return strconv.Atoi(idStr)
}

func (h *RuleHandler) ListByApp(w http.ResponseWriter, r *http.Request) {
	appID := extractAppIDFromRulePath(r.URL.Path)
	if appID == "" {
		respondError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	rules, err := h.ruleService.ListRulesByApp(appID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]dto.RuleResponse, len(rules))
	for i, r := range rules {
		resp[i] = toRuleResponse(r)
	}

	respondJSON(w, http.StatusOK, resp)
}

func (h *RuleHandler) CreateForApp(w http.ResponseWriter, r *http.Request) {
	appID := extractAppIDFromRulePath(r.URL.Path)
	if appID == "" {
		respondError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	var req dto.RuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" || req.ExpressionRaw == "" || req.Action == "" {
		respondError(w, http.StatusBadRequest, "Missing required fields")
		return
	}

	req.Scope = "app"
	req.AppID = appID

	compiledRule, err := h.ruleService.CreateRule(
		req.ExpressionRaw,
		req.Name,
		req.Scope,
		req.RuleGroup,
		req.Action,
		req.Description,
		req.AppID,
		req.SkipModules,
		req.Priority,
		req.Enabled,
	)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, toRuleResponse(compiledRule))
}

func (h *RuleHandler) UpdateForApp(w http.ResponseWriter, r *http.Request) {
	appID := extractAppIDFromRulePath(r.URL.Path)
	if appID == "" {
		respondError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	id, err := extractIDFromRuleAppPath(r.URL.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	existing, err := h.ruleService.GetRule(id)
	if err != nil || existing.AppID != appID {
		respondError(w, http.StatusNotFound, "security rule not found")
		return
	}

	var req dto.RuleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	compiledRule, err := h.ruleService.UpdateRule(
		id,
		req.ExpressionRaw,
		req.Name,
		req.Scope,
		req.RuleGroup,
		req.Action,
		req.Description,
		req.AppID,
		req.SkipModules,
		req.Priority,
		req.Enabled,
	)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, toRuleResponse(compiledRule))
}

func (h *RuleHandler) DeleteForApp(w http.ResponseWriter, r *http.Request) {
	appID := extractAppIDFromRulePath(r.URL.Path)
	if appID == "" {
		respondError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	id, err := extractIDFromRuleAppPath(r.URL.Path)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rule ID")
		return
	}

	existing, err := h.ruleService.GetRule(id)
	if err != nil || existing.AppID != appID {
		respondError(w, http.StatusNotFound, "security rule not found")
		return
	}

	if err := h.ruleService.DeleteRule(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Rule deleted successfully",
	})
}

func (h *RuleHandler) ReorderForApp(w http.ResponseWriter, r *http.Request) {
	appID := extractAppIDFromRulePath(r.URL.Path)
	if appID == "" {
		respondError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	var req dto.RuleReorderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.ruleService.ReorderRules(req.RuleIDs); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Rules reordered successfully",
	})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, dto.ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}


func (h *RuleHandler) ReorderRules(w http.ResponseWriter, r *http.Request) {
	var req dto.RuleReorderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.ruleService.ReorderRules(req.RuleIDs); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Rules reordered successfully",
	})
}

// GetRuleEvents returns event counts per rule ID from ClickHouse.
func (h *RuleHandler) GetRuleEvents(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	daysStr := r.URL.Query().Get("days")
	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	// reason format: "rule:ID:name|rule:ID:name|..."
	// Extract the numeric ID from each rule segment.
	query := `
		SELECT
			toUInt64OrZero(splitByChar(':', r)[2]) as rule_id,
			count() as event_count
		FROM (
			SELECT arrayJoin(splitByChar('|', reason)) as r
			FROM waf_events
			WHERE ts >= now() - INTERVAL ? DAY
		)
		WHERE r LIKE 'rule:%'
		  AND length(splitByChar(':', r)) >= 2
		  AND toUInt64OrZero(splitByChar(':', r)[2]) > 0
		GROUP BY rule_id
	`

	ctx := context.Background()
	rows, err := h.logger.Conn().Query(ctx, query, days)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query rule events: "+err.Error())
		return
	}
	defer rows.Close()

	eventCounts := make(map[uint64]uint64)
	for rows.Next() {
		var ruleID uint64
		var count uint64
		if err := rows.Scan(&ruleID, &count); err != nil {
			continue
		}
		eventCounts[ruleID] = count
	}

	respondJSON(w, http.StatusOK, eventCounts)
}
