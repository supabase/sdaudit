package reliability

import (
	"strings"

	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func init() {
	rules.Register(&REL003{})
	rules.Register(&REL004{})
	rules.Register(&REL005{})
	rules.Register(&REL006{})
	rules.Register(&REL007{})
	rules.Register(&REL008{})
	rules.Register(&REL009{})
	rules.Register(&REL010{})
}

// REL003 - Missing WantedBy/RequiredBy
type REL003 struct{}

func (r *REL003) ID() string   { return "REL003" }
func (r *REL003) Name() string { return "Missing WantedBy or RequiredBy" }
func (r *REL003) Description() string {
	return "Services should specify how they integrate with targets."
}
func (r *REL003) Category() types.Category { return types.CategoryReliability }
func (r *REL003) Severity() types.Severity { return types.SeverityMedium }
func (r *REL003) Tags() []string           { return []string{"install", "targets"} }
func (r *REL003) Suggestion() string       { return "Add 'WantedBy=multi-user.target' to [Install] section." }
func (r *REL003) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#WantedBy="}
}
func (r *REL003) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	wantedBy := unit.GetDirective("Install", "WantedBy")
	requiredBy := unit.GetDirective("Install", "RequiredBy")
	if wantedBy == "" && requiredBy == "" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service has no WantedBy or RequiredBy, won't start automatically.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// REL004 - Circular dependency (simplified check)
type REL004 struct{}

func (r *REL004) ID() string               { return "REL004" }
func (r *REL004) Name() string             { return "Potential circular dependency" }
func (r *REL004) Description() string      { return "Units should not have circular dependencies." }
func (r *REL004) Category() types.Category { return types.CategoryReliability }
func (r *REL004) Severity() types.Severity { return types.SeverityCritical }
func (r *REL004) Tags() []string           { return []string{"dependency", "boot"} }
func (r *REL004) Suggestion() string       { return "Review dependency chain and remove cycles." }
func (r *REL004) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Requires="}
}
func (r *REL004) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || len(ctx.AllUnits) == 0 {
		return nil
	}
	// Check if unit references itself
	deps := []string{}
	for _, d := range []string{"Requires", "Wants", "After", "Before", "BindsTo"} {
		if v := unit.GetDirective("Unit", d); v != "" {
			deps = append(deps, strings.Fields(v)...)
		}
	}
	for _, dep := range deps {
		if dep == unit.Name {
			return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Unit references itself in dependencies.", Suggestion: r.Suggestion(), References: r.References()}}
		}
	}
	return nil
}

// REL005 - After without Requires
type REL005 struct{}

func (r *REL005) ID() string   { return "REL005" }
func (r *REL005) Name() string { return "After without Requires or Wants" }
func (r *REL005) Description() string {
	return "After= only orders startup, doesn't ensure dependency starts."
}
func (r *REL005) Category() types.Category { return types.CategoryReliability }
func (r *REL005) Severity() types.Severity { return types.SeverityLow }
func (r *REL005) Tags() []string           { return []string{"dependency", "ordering"} }
func (r *REL005) Suggestion() string {
	return "Add corresponding Requires= or Wants= for After= dependencies."
}
func (r *REL005) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#After="}
}
func (r *REL005) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil {
		return nil
	}
	after := strings.Fields(unit.GetDirective("Unit", "After"))
	requires := strings.Fields(unit.GetDirective("Unit", "Requires"))
	wants := strings.Fields(unit.GetDirective("Unit", "Wants"))
	bindsTo := strings.Fields(unit.GetDirective("Unit", "BindsTo"))

	ensured := make(map[string]bool)
	for _, u := range requires {
		ensured[u] = true
	}
	for _, u := range wants {
		ensured[u] = true
	}
	for _, u := range bindsTo {
		ensured[u] = true
	}

	// Skip common targets that don't need explicit Requires
	skip := map[string]bool{"network.target": true, "network-online.target": true, "local-fs.target": true, "remote-fs.target": true, "sysinit.target": true, "basic.target": true, "multi-user.target": true}

	for _, a := range after {
		if !ensured[a] && !skip[a] && !strings.HasSuffix(a, ".target") {
			return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "After=" + a + " without Requires/Wants may not start the dependency.", Suggestion: r.Suggestion(), References: r.References()}}
		}
	}
	return nil
}

// REL006 - StartLimitBurst not set
type REL006 struct{}

func (r *REL006) ID() string               { return "REL006" }
func (r *REL006) Name() string             { return "StartLimitBurst not configured" }
func (r *REL006) Description() string      { return "Services should configure start rate limiting." }
func (r *REL006) Category() types.Category { return types.CategoryReliability }
func (r *REL006) Severity() types.Severity { return types.SeverityMedium }
func (r *REL006) Tags() []string           { return []string{"restart-loop", "rate-limiting"} }
func (r *REL006) Suggestion() string {
	return "Add 'StartLimitBurst=5' and 'StartLimitIntervalSec=10' to [Unit]."
}
func (r *REL006) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#StartLimitBurst="}
}
func (r *REL006) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	restart := unit.GetDirective("Service", "Restart")
	if restart == "" || restart == "no" {
		return nil
	}
	burst := unit.GetDirective("Unit", "StartLimitBurst")
	interval := unit.GetDirective("Unit", "StartLimitIntervalSec")
	if burst == "" && interval == "" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service has restart but no start rate limiting.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// REL007 - Missing ExecStop
type REL007 struct{}

func (r *REL007) ID() string   { return "REL007" }
func (r *REL007) Name() string { return "Missing ExecStop for graceful shutdown" }
func (r *REL007) Description() string {
	return "Long-running services may need explicit stop commands."
}
func (r *REL007) Category() types.Category { return types.CategoryReliability }
func (r *REL007) Severity() types.Severity { return types.SeverityLow }
func (r *REL007) Tags() []string           { return []string{"shutdown", "graceful"} }
func (r *REL007) Suggestion() string       { return "Consider adding ExecStop= if SIGTERM isn't sufficient." }
func (r *REL007) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#ExecStop="}
}
func (r *REL007) Check(ctx *rules.Context) []types.Issue {
	// This is advisory only - many services handle SIGTERM fine
	return nil
}

// REL008 - KillMode=none
type REL008 struct{}

func (r *REL008) ID() string               { return "REL008" }
func (r *REL008) Name() string             { return "KillMode set to none" }
func (r *REL008) Description() string      { return "KillMode=none leaves processes orphaned." }
func (r *REL008) Category() types.Category { return types.CategoryReliability }
func (r *REL008) Severity() types.Severity { return types.SeverityHigh }
func (r *REL008) Tags() []string           { return []string{"shutdown", "orphan"} }
func (r *REL008) Suggestion() string       { return "Use KillMode=control-group or mixed instead of none." }
func (r *REL008) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.kill.html#KillMode="}
}
func (r *REL008) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "KillMode"); v == "none" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "KillMode=none leaves child processes orphaned on stop.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// REL009 - Dependency on masked unit
type REL009 struct{}

func (r *REL009) ID() string               { return "REL009" }
func (r *REL009) Name() string             { return "Dependency on missing unit" }
func (r *REL009) Description() string      { return "Unit depends on another unit that doesn't exist." }
func (r *REL009) Category() types.Category { return types.CategoryReliability }
func (r *REL009) Severity() types.Severity { return types.SeverityHigh }
func (r *REL009) Tags() []string           { return []string{"dependency", "missing"} }
func (r *REL009) Suggestion() string       { return "Remove or fix the dependency on missing unit." }
func (r *REL009) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Requires="}
}
func (r *REL009) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || len(ctx.AllUnits) == 0 {
		return nil
	}
	requires := strings.Fields(unit.GetDirective("Unit", "Requires"))
	for _, req := range requires {
		if strings.HasSuffix(req, ".service") {
			if _, exists := ctx.AllUnits[req]; !exists {
				return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Required unit not found: " + req, Suggestion: r.Suggestion(), References: r.References()}}
			}
		}
	}
	return nil
}

// REL010 - BindsTo without After
type REL010 struct{}

func (r *REL010) ID() string               { return "REL010" }
func (r *REL010) Name() string             { return "BindsTo without After" }
func (r *REL010) Description() string      { return "BindsTo should usually be paired with After." }
func (r *REL010) Category() types.Category { return types.CategoryReliability }
func (r *REL010) Severity() types.Severity { return types.SeverityMedium }
func (r *REL010) Tags() []string           { return []string{"dependency", "ordering"} }
func (r *REL010) Suggestion() string       { return "Add After= for units listed in BindsTo=." }
func (r *REL010) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#BindsTo="}
}
func (r *REL010) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil {
		return nil
	}
	bindsTo := strings.Fields(unit.GetDirective("Unit", "BindsTo"))
	after := strings.Fields(unit.GetDirective("Unit", "After"))
	afterSet := make(map[string]bool)
	for _, a := range after {
		afterSet[a] = true
	}
	for _, b := range bindsTo {
		if !afterSet[b] {
			return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "BindsTo=" + b + " without corresponding After=.", Suggestion: r.Suggestion(), References: r.References()}}
		}
	}
	return nil
}
