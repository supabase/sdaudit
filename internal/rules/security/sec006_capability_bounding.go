package security

import (
	"strings"

	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC006{})
}

type SEC006 struct{}

func (r *SEC006) ID() string   { return "SEC006" }
func (r *SEC006) Name() string { return "CapabilityBoundingSet too permissive" }
func (r *SEC006) Description() string {
	return "Services should restrict capabilities to only those needed."
}
func (r *SEC006) Category() types.Category { return types.CategorySecurity }
func (r *SEC006) Severity() types.Severity { return types.SeverityHigh }
func (r *SEC006) Tags() []string           { return []string{"hardening", "capabilities"} }
func (r *SEC006) Suggestion() string {
	return "Set 'CapabilityBoundingSet=' to only the capabilities the service needs, or use '~CAP_SYS_ADMIN' to drop dangerous ones."
}
func (r *SEC006) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#CapabilityBoundingSet="}
}

func (r *SEC006) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	value := unit.GetDirective("Service", "CapabilityBoundingSet")
	if value == "" {
		return []types.Issue{{
			RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(),
			Tags: r.Tags(), Unit: unit.Name, File: unit.Path,
			Description: "Service does not restrict Linux capabilities.",
			Suggestion:  r.Suggestion(), References: r.References(),
		}}
	}

	// Check for dangerous capabilities
	dangerous := []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"}
	for _, cap := range dangerous {
		if strings.Contains(value, cap) && !strings.Contains(value, "~"+cap) {
			return []types.Issue{{
				RuleID: r.ID(), RuleName: r.Name(), Severity: types.SeverityMedium, Category: r.Category(),
				Tags: r.Tags(), Unit: unit.Name, File: unit.Path,
				Description: "Service allows dangerous capability: " + cap,
				Suggestion:  r.Suggestion(), References: r.References(),
			}}
		}
	}

	return nil
}
