package security

import (
	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC005{})
}

type SEC005 struct{}

func (r *SEC005) ID() string   { return "SEC005" }
func (r *SEC005) Name() string { return "Service running as root without hardening" }
func (r *SEC005) Description() string {
	return "Services running as root should have comprehensive security hardening."
}
func (r *SEC005) Category() types.Category { return types.CategorySecurity }
func (r *SEC005) Severity() types.Severity { return types.SeverityCritical }
func (r *SEC005) Tags() []string           { return []string{"hardening", "privilege", "root"} }
func (r *SEC005) Suggestion() string {
	return "Use 'User=' to run as non-root, or 'DynamicUser=yes', or add comprehensive hardening."
}
func (r *SEC005) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#User="}
}

func (r *SEC005) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	user := unit.GetDirective("Service", "User")
	dynamicUser := unit.GetDirective("Service", "DynamicUser")

	if (user != "" && user != "root") || dynamicUser == "yes" || dynamicUser == "true" {
		return nil
	}

	// Check hardening score
	score := 0
	checks := map[string][]string{
		"NoNewPrivileges":       {"yes", "true"},
		"ProtectSystem":         {"strict", "full"},
		"ProtectHome":           {"yes", "true", "read-only", "tmpfs"},
		"PrivateTmp":            {"yes", "true"},
		"PrivateDevices":        {"yes", "true"},
		"ProtectKernelTunables": {"yes", "true"},
		"ProtectKernelModules":  {"yes", "true"},
	}

	for directive, goodValues := range checks {
		val := unit.GetDirective("Service", directive)
		for _, good := range goodValues {
			if val == good {
				score++
				break
			}
		}
	}

	if score >= 4 {
		return nil
	}

	return []types.Issue{{
		RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(),
		Tags: r.Tags(), Unit: unit.Name, File: unit.Path,
		Description: "Service runs as root without adequate security hardening.",
		Suggestion:  r.Suggestion(), References: r.References(),
	}}
}
