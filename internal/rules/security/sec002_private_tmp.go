package security

import (
	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC002{})
}

type SEC002 struct{}

func (r *SEC002) ID() string   { return "SEC002" }
func (r *SEC002) Name() string { return "PrivateTmp not enabled" }

func (r *SEC002) Description() string {
	return "Services should enable PrivateTmp=yes to use a private /tmp namespace."
}

func (r *SEC002) Category() types.Category { return types.CategorySecurity }
func (r *SEC002) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC002) Tags() []string           { return []string{"hardening", "isolation", "sandbox"} }

func (r *SEC002) Suggestion() string {
	return "Add 'PrivateTmp=yes' to the [Service] section."
}

func (r *SEC002) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateTmp="}
}

func (r *SEC002) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	value := unit.GetDirective("Service", "PrivateTmp")
	if value == "" || value == "no" || value == "false" {
		return []types.Issue{{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.Severity(),
			Category:    r.Category(),
			Tags:        r.Tags(),
			Unit:        unit.Name,
			File:        unit.Path,
			Description: "Service does not enable PrivateTmp, exposing it to symlink attacks through /tmp.",
			Suggestion:  r.Suggestion(),
			References:  r.References(),
		}}
	}
	return nil
}
