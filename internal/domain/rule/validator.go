package rule

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vibeswaf/waf/internal/rules"
)


type Validator struct{}


func NewValidator() *Validator {
	return &Validator{}
}


func (v *Validator) Validate(node *Node) error {
	if node == nil {
		return fmt.Errorf("node is nil")
	}

	switch node.Type {
	case NodeComparison:
		return v.validateComparison(node)
	case NodeLogical:
		if node.Left != nil {
			if err := v.Validate(node.Left); err != nil {
				return err
			}
		}
		if node.Right != nil {
			if err := v.Validate(node.Right); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown node type: %v", node.Type)
	}
}


func (v *Validator) validateComparison(node *Node) error {

	if !v.isValidField(node.Field) {
		return fmt.Errorf("unknown field: %s", node.Field)
	}


	if !v.isValidOperator(node.Operator) {
		return fmt.Errorf("unknown operator: %s", node.Operator)
	}


	if node.Operator == "regex" || node.Operator == "not_regex" {
		if err := v.validateRegex(toString(node.Value)); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	return nil
}


func (v *Validator) isValidField(field string) bool {

	_, exists := rules.FieldRegistry[field]
	return exists
}


func (v *Validator) isValidOperator(operator string) bool {
	validOperators := []string{
		"eq", "neq", "in", "not_in",
		"contains", "not_contains",
		"prefix", "suffix",
		"regex", "not_regex",
		"gt", "lt", "gte", "lte",
		"exists", "not_exists",
	}
	for _, op := range validOperators {
		if op == operator {
			return true
		}
	}
	return false
}


func (v *Validator) validateRegex(pattern string) error {

	if len(pattern) > 500 {
		return fmt.Errorf("regex pattern too long (max 500 characters)")
	}


	dangerousPatterns := []string{
		`(a+)+`,
		`(a*)*`,
		`(a|a)*`,
		`(a|ab)*`,
		`([a-zA-Z]+)*`,
	}

	for _, dangerous := range dangerousPatterns {
		if strings.Contains(pattern, dangerous) {
			return fmt.Errorf("regex pattern may cause ReDoS attack")
		}
	}


	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex syntax: %w", err)
	}

	return nil
}
