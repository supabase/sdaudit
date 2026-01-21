package security

import (
	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC001{})
}

type SEC001 struct{}

func (r *SEC001) ID() string   { return "SEC001" }
func (r *SEC001) Name() string { return "NoNewPrivileges not set" }

func (r *SEC001) Description() string {
	return "Services should set NoNewPrivileges=yes to prevent privilege escalation through setuid/setgid binaries."
}

func (r *SEC001) Category() types.Category { return types.CategorySecurity }
func (r *SEC001) Severity() types.Severity { return types.SeverityHigh }
func (r *SEC001) Tags() []string           { return []string{"hardening", "privilege-escalation", "sandbox"} }

func (r *SEC001) Suggestion() string {
	return "Add 'NoNewPrivileges=yes' to the [Service] section."
}

func (r *SEC001) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#NoNewPrivileges="}
}

func (r *SEC001) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	value := unit.GetDirective("Service", "NoNewPrivileges")
	if value == "" || value == "no" || value == "false" {
		return []types.Issue{{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.Severity(),
			Category:    r.Category(),
			Tags:        r.Tags(),
			Unit:        unit.Name,
			File:        unit.Path,
			Description: "Service does not set NoNewPrivileges=yes, allowing potential privilege escalation.",
			Suggestion:  r.Suggestion(),
			References:  r.References(),
		}}
	}
	return nil
}
