package rule

import (
	"github.com/vibeswaf/waf/internal/rules"
)


type Engine struct {
	evaluator *Evaluator
}


func NewEngine() *Engine {
	return &Engine{
		evaluator: NewEvaluator(),
	}
}


func (e *Engine) Execute(rule *CompiledRule, ctx RequestContext) (bool, error) {
	if rule == nil || rule.AST == nil {
		return false, nil
	}

	return e.evaluator.Evaluate(rule.AST, ctx)
}


func (e *Engine) ValidateExpression(expression string) error {

	lexer := NewLexer(expression)
	tokens, err := lexer.Tokenize()
	if err != nil {
		return err
	}


	parser := NewParser(tokens)
	ast, err := parser.Parse()
	if err != nil {
		return err
	}


	validator := NewValidator()
	return validator.Validate(ast)
}


func (e *Engine) CompileExpression(expression string) (*Node, error) {

	lexer := NewLexer(expression)
	tokens, err := lexer.Tokenize()
	if err != nil {
		return nil, err
	}


	parser := NewParser(tokens)
	ast, err := parser.Parse()
	if err != nil {
		return nil, err
	}


	validator := NewValidator()
	if err := validator.Validate(ast); err != nil {
		return nil, err
	}

	return ast, nil
}


type FieldMetadata struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	AllowedOperators []string `json:"allowed_operators"`
	Description      string   `json:"description"`
}


func (e *Engine) GetFieldMetadata() []FieldMetadata {
	metadata := make([]FieldMetadata, 0, len(rules.FieldRegistry))
	
	for _, field := range rules.FieldRegistry {
		var fieldType string
		switch field.Type {
		case rules.FieldTypeString:
			fieldType = "string"
		case rules.FieldTypeInt:
			fieldType = "int"
		case rules.FieldTypeBool:
			fieldType = "bool"
		case rules.FieldTypeIP:
			fieldType = "ip"
		}
		
		metadata = append(metadata, FieldMetadata{
			Name:             field.Name,
			Type:             fieldType,
			AllowedOperators: field.AllowedOps,
			Description:      field.Description,
		})
	}
	
	return metadata
}
