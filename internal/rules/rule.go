package rules

import (
	"github.com/supabase/sdaudit/pkg/types"
)

// Rule defines the interface that all rules must implement
type Rule interface {
	ID() string
	Name() string
	Description() string
	Category() types.Category
	Severity() types.Severity
	Tags() []string
	Check(ctx *Context) []types.Issue
	Suggestion() string
	References() []string
}

// BaseRule provides a partial implementation of Rule that can be embedded
type BaseRule struct {
	RuleID          string
	RuleName        string
	RuleDescription string
	RuleCategory    types.Category
	RuleSeverity    types.Severity
	RuleTags        []string
	RuleSuggestion  string
	RuleReferences  []string
}

func (r *BaseRule) ID() string               { return r.RuleID }
func (r *BaseRule) Name() string             { return r.RuleName }
func (r *BaseRule) Description() string      { return r.RuleDescription }
func (r *BaseRule) Category() types.Category { return r.RuleCategory }
func (r *BaseRule) Severity() types.Severity { return r.RuleSeverity }
func (r *BaseRule) Tags() []string           { return r.RuleTags }
func (r *BaseRule) Suggestion() string       { return r.RuleSuggestion }
func (r *BaseRule) References() []string     { return r.RuleReferences }

// NewIssue creates an Issue from this rule for a specific unit
func (r *BaseRule) NewIssue(unit *types.UnitFile, description string, line *int) types.Issue {
	return types.Issue{
		RuleID:      r.RuleID,
		RuleName:    r.RuleName,
		Severity:    r.RuleSeverity,
		Category:    r.RuleCategory,
		Tags:        r.RuleTags,
		Unit:        unit.Name,
		File:        unit.Path,
		Line:        line,
		Description: description,
		Suggestion:  r.RuleSuggestion,
		References:  r.RuleReferences,
	}
}
