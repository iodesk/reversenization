package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/pipeline"
)

const maxRegexCache = 500

type Evaluator struct {
	fields          map[string]FieldDef
	operators       map[string]OperatorDef
	regexCache      map[string]*regexp.Regexp
	regexCacheOrder []string
	regexCacheMu    sync.RWMutex
	appConfig       *config.AppConfig
}

func NewEvaluator() *Evaluator {
	return &Evaluator{
		fields:          FieldRegistry,
		operators:       OperatorRegistry,
		regexCache:      make(map[string]*regexp.Regexp),
		regexCacheOrder: make([]string, 0, maxRegexCache),
		appConfig:       config.GetAppConfig(),
	}
}
func (e *Evaluator) Evaluate(node *Node, ctx *pipeline.Context) (bool, error) {
	if node == nil {
		return false, fmt.Errorf("node is nil")
	}

	switch node.Type {
	case NodeCondition:
		return e.evaluateCondition(node, ctx)

	case NodeAnd:
		left, err := e.Evaluate(node.Left, ctx)
		if err != nil {
			return false, err
		}
		if !left {
			return false, nil
		}
		return e.Evaluate(node.Right, ctx)

	case NodeOr:
		left, err := e.Evaluate(node.Left, ctx)
		if err != nil {
			return false, err
		}
		if left {
			return true, nil
		}
		return e.Evaluate(node.Right, ctx)

	case NodeNot:
		result, err := e.Evaluate(node.Left, ctx)
		return !result, err

	default:
		return false, fmt.Errorf("unknown node type: %v", node.Type)
	}
}

func (e *Evaluator) evaluateCondition(node *Node, ctx *pipeline.Context) (bool, error) {

	fieldDef, exists := e.fields[node.Field]
	if !exists {
		return false, fmt.Errorf("unknown field: %s", node.Field)
	}

	fieldValue := fieldDef.Extractor(ctx)

	opDef, exists := e.operators[node.Operator]
	if !exists {
		return false, fmt.Errorf("unknown operator: %s", node.Operator)
	}

	if node.Operator == "regex" || node.Operator == "not_regex" {
		return e.evaluateRegex(node, fieldValue)
	}

	ruleValue := e.parseValue(node.Value, fieldDef.Type)

	// Debug logging for boolean field comparisons
	if fieldDef.Type == FieldTypeBool {
		e.appConfig.LogDebug("[RULES] Evaluating %s %s %v: fieldValue=%v (type:%T), ruleValue=%v (type:%T)",
			node.Field, node.Operator, node.Value, fieldValue, fieldValue, ruleValue, ruleValue)
	}

	result, err := opDef.Evaluator(fieldValue, ruleValue)
	
	// Log result for boolean fields
	if fieldDef.Type == FieldTypeBool {
		e.appConfig.LogDebug("[RULES] Evaluation result for %s: %v", node.Field, result)
	}

	return result, err
}

func (e *Evaluator) evaluateRegex(node *Node, fieldValue interface{}) (bool, error) {
	pattern := node.Value

	e.regexCacheMu.RLock()
	re, cached := e.regexCache[pattern]
	e.regexCacheMu.RUnlock()

	if !cached {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex: %w", err)
		}

		e.regexCacheMu.Lock()
		if len(e.regexCache) >= maxRegexCache {
			delete(e.regexCache, e.regexCacheOrder[0])
			e.regexCacheOrder = e.regexCacheOrder[1:]
		}
		e.regexCache[pattern] = re
		e.regexCacheOrder = append(e.regexCacheOrder, pattern)
		e.regexCacheMu.Unlock()
	}
fv := toString(fieldValue)
	matched := re.MatchString(fv)

	if node.Operator == "not_regex" {
		return !matched, nil
	}
	return matched, nil
}

func (e *Evaluator) parseValue(value interface{}, fieldType FieldType) interface{} {
	// If value is already the correct type, return it
	if fieldType == FieldTypeBool {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	
	// Convert to string for parsing
	valueStr := toString(value)
	
	switch fieldType {
	case FieldTypeInt:
		return toInt(valueStr)

	case FieldTypeBool:
		return valueStr == "true"

	case FieldTypeString:
		if strings.HasPrefix(valueStr, "[") && strings.HasSuffix(valueStr, "]") {
			return e.parseArray(valueStr)
		}
		return valueStr

	case FieldTypeIP:
		return valueStr

	default:
		return valueStr
	}
}

func (e *Evaluator) parseArray(value string) []string {

	value = strings.Trim(value, "[]")

	parts := strings.Split(value, ",")

	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "\"")
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return fmt.Sprintf("%d", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case string:
		num := 0
		for _, c := range val {
			if c >= '0' && c <= '9' {
				num = num*10 + int(c-'0')
			}
		}
		return num
	default:
		return 0
	}
}
