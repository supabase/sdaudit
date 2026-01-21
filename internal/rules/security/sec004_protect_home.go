package security

import (
	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC004{})
}

type SEC004 struct{}

func (r *SEC004) ID() string   { return "SEC004" }
func (r *SEC004) Name() string { return "ProtectHome not enabled" }
func (r *SEC004) Description() string {
	return "Services should enable ProtectHome to prevent access to user home directories."
}
func (r *SEC004) Category() types.Category { return types.CategorySecurity }
func (r *SEC004) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC004) Tags() []string           { return []string{"hardening", "filesystem", "privacy"} }
func (r *SEC004) Suggestion() string       { return "Add 'ProtectHome=yes' to the [Service] section." }
func (r *SEC004) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectHome="}
}

func (r *SEC004) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	value := unit.GetDirective("Service", "ProtectHome")
	if value == "" || value == "no" || value == "false" {
		return []types.Issue{{
			RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(),
			Tags: r.Tags(), Unit: unit.Name, File: unit.Path,
			Description: "Service does not protect home directories from access.",
			Suggestion:  r.Suggestion(), References: r.References(),
		}}
	}
	return nil
}
