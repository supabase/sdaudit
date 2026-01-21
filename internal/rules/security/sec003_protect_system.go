package security

import (
	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC003{})
}

type SEC003 struct{}

func (r *SEC003) ID() string   { return "SEC003" }
func (r *SEC003) Name() string { return "ProtectSystem not set or weak" }

func (r *SEC003) Description() string {
	return "Services should set ProtectSystem=strict to make system directories read-only."
}

func (r *SEC003) Category() types.Category { return types.CategorySecurity }
func (r *SEC003) Severity() types.Severity { return types.SeverityHigh }
func (r *SEC003) Tags() []string           { return []string{"hardening", "filesystem", "sandbox"} }

func (r *SEC003) Suggestion() string {
	return "Add 'ProtectSystem=strict' to the [Service] section."
}

func (r *SEC003) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectSystem="}
}

func (r *SEC003) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	value := unit.GetDirective("Service", "ProtectSystem")
	switch value {
	case "strict", "full":
		return nil
	case "yes", "true":
		return []types.Issue{{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    types.SeverityLow,
			Category:    r.Category(),
			Tags:        r.Tags(),
			Unit:        unit.Name,
			File:        unit.Path,
			Description: "Service uses ProtectSystem=yes which only protects /usr and /boot. Consider 'strict'.",
			Suggestion:  r.Suggestion(),
			References:  r.References(),
		}}
	default:
		return []types.Issue{{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.Severity(),
			Category:    r.Category(),
			Tags:        r.Tags(),
			Unit:        unit.Name,
			File:        unit.Path,
			Description: "Service does not set ProtectSystem, allowing modification of system directories.",
			Suggestion:  r.Suggestion(),
			References:  r.References(),
		}}
	}
}
