package bestpractice

import (
	"os/user"
	"strings"

	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&BP001{})
	rules.Register(&BP002{})
	rules.Register(&BP003{})
	rules.Register(&BP004{})
	rules.Register(&BP005{})
	rules.Register(&BP006{})
	rules.Register(&BP007{})
	rules.Register(&BP008{})
	rules.Register(&BP009{})
	rules.Register(&BP010{})
}

// BP001 - Override in /etc without drop-in
type BP001 struct{}

func (r *BP001) ID() string   { return "BP001" }
func (r *BP001) Name() string { return "Full override in /etc instead of drop-in" }
func (r *BP001) Description() string {
	return "Prefer drop-ins over full overrides for maintainability."
}
func (r *BP001) Category() types.Category { return types.CategoryBestPractice }
func (r *BP001) Severity() types.Severity { return types.SeverityInfo }
func (r *BP001) Tags() []string           { return []string{"override", "maintainability"} }
func (r *BP001) Suggestion() string       { return "Use /etc/systemd/system/unit.d/*.conf drop-ins instead." }
func (r *BP001) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html"}
}
func (r *BP001) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil {
		return nil
	}
	if strings.HasPrefix(unit.Path, "/etc/systemd/system/") && !strings.Contains(unit.Path, ".d/") {
		// Check if there's a corresponding unit in /lib
		libPath := strings.Replace(unit.Path, "/etc/systemd/system/", "/lib/systemd/system/", 1)
		if _, exists := ctx.AllUnits[unit.Name]; exists && strings.HasPrefix(libPath, "/lib") {
			return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Full override in /etc, consider drop-in instead.", Suggestion: r.Suggestion(), References: r.References()}}
		}
	}
	return nil
}

// BP002 - Deprecated directives
type BP002 struct{}

func (r *BP002) ID() string   { return "BP002" }
func (r *BP002) Name() string { return "Deprecated directive used" }
func (r *BP002) Description() string {
	return "Some directives are deprecated in newer systemd versions."
}
func (r *BP002) Category() types.Category { return types.CategoryBestPractice }
func (r *BP002) Severity() types.Severity { return types.SeverityMedium }
func (r *BP002) Tags() []string           { return []string{"deprecated"} }
func (r *BP002) Suggestion() string       { return "Update to the current directive name." }
func (r *BP002) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.directives.html"}
}
func (r *BP002) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil {
		return nil
	}
	deprecated := map[string]string{
		"PermissionsStartOnly": "Use '+' prefix in ExecStart= instead",
		"StartLimitInterval":   "Use StartLimitIntervalSec= instead",
	}
	for section := range unit.Sections {
		for directive, replacement := range deprecated {
			if unit.HasDirective(section, directive) {
				return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: directive + " is deprecated. " + replacement, Suggestion: r.Suggestion(), References: r.References()}}
			}
		}
	}
	return nil
}

// BP003 - ExecStart without absolute path
type BP003 struct{}

func (r *BP003) ID() string               { return "BP003" }
func (r *BP003) Name() string             { return "ExecStart not using absolute path" }
func (r *BP003) Description() string      { return "ExecStart should use absolute paths for reliability." }
func (r *BP003) Category() types.Category { return types.CategoryBestPractice }
func (r *BP003) Severity() types.Severity { return types.SeverityMedium }
func (r *BP003) Tags() []string           { return []string{"paths", "reliability"} }
func (r *BP003) Suggestion() string       { return "Use absolute path in ExecStart=." }
func (r *BP003) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#ExecStart="}
}
func (r *BP003) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	execStart := unit.GetDirective("Service", "ExecStart")
	if execStart == "" {
		return nil
	}
	// Strip prefixes like -, +, !, @
	cmd := strings.TrimLeft(execStart, "-+!@")
	cmd = strings.Fields(cmd)[0]
	if !strings.HasPrefix(cmd, "/") {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "ExecStart does not use absolute path: " + cmd, Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// BP004 - Missing Documentation
type BP004 struct{}

func (r *BP004) ID() string   { return "BP004" }
func (r *BP004) Name() string { return "Missing Documentation directive" }
func (r *BP004) Description() string {
	return "Units should include Documentation= for discoverability."
}
func (r *BP004) Category() types.Category { return types.CategoryBestPractice }
func (r *BP004) Severity() types.Severity { return types.SeverityInfo }
func (r *BP004) Tags() []string           { return []string{"documentation"} }
func (r *BP004) Suggestion() string       { return "Add Documentation= to [Unit] section." }
func (r *BP004) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Documentation="}
}
func (r *BP004) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil {
		return nil
	}
	if unit.GetDirective("Unit", "Documentation") == "" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Unit has no Documentation directive.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// BP005 - Environment in unit file
type BP005 struct{}

func (r *BP005) ID() string               { return "BP005" }
func (r *BP005) Name() string             { return "Environment variables in unit file" }
func (r *BP005) Description() string      { return "Consider using EnvironmentFile= for maintainability." }
func (r *BP005) Category() types.Category { return types.CategoryBestPractice }
func (r *BP005) Severity() types.Severity { return types.SeverityInfo }
func (r *BP005) Tags() []string           { return []string{"environment", "maintainability"} }
func (r *BP005) Suggestion() string       { return "Move environment variables to EnvironmentFile=." }
func (r *BP005) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#EnvironmentFile="}
}
func (r *BP005) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	envs := unit.GetDirectives("Service", "Environment")
	if len(envs) > 3 {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service has many inline Environment= directives.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// BP006 - Hardcoded paths
type BP006 struct{}

func (r *BP006) ID() string   { return "BP006" }
func (r *BP006) Name() string { return "Hardcoded paths instead of specifiers" }
func (r *BP006) Description() string {
	return "Use systemd specifiers like %t, %h instead of hardcoded paths."
}
func (r *BP006) Category() types.Category { return types.CategoryBestPractice }
func (r *BP006) Severity() types.Severity { return types.SeverityInfo }
func (r *BP006) Tags() []string           { return []string{"specifiers", "portability"} }
func (r *BP006) Suggestion() string       { return "Use %t for runtime dir, %h for home, etc." }
func (r *BP006) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Specifiers"}
}
func (r *BP006) Check(ctx *rules.Context) []types.Issue {
	// Advisory - hard to detect automatically
	return nil
}

// BP007 - Missing WorkingDirectory
type BP007 struct{}

func (r *BP007) ID() string               { return "BP007" }
func (r *BP007) Name() string             { return "WorkingDirectory not set" }
func (r *BP007) Description() string      { return "Consider setting explicit WorkingDirectory." }
func (r *BP007) Category() types.Category { return types.CategoryBestPractice }
func (r *BP007) Severity() types.Severity { return types.SeverityInfo }
func (r *BP007) Tags() []string           { return []string{"paths"} }
func (r *BP007) Suggestion() string       { return "Add WorkingDirectory= to [Service] section." }
func (r *BP007) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#WorkingDirectory="}
}
func (r *BP007) Check(ctx *rules.Context) []types.Issue {
	// Advisory only
	return nil
}

// BP008 - Missing Description
type BP008 struct{}

func (r *BP008) ID() string               { return "BP008" }
func (r *BP008) Name() string             { return "Missing Description" }
func (r *BP008) Description() string      { return "Units should have a Description for clarity." }
func (r *BP008) Category() types.Category { return types.CategoryBestPractice }
func (r *BP008) Severity() types.Severity { return types.SeverityInfo }
func (r *BP008) Tags() []string           { return []string{"documentation"} }
func (r *BP008) Suggestion() string       { return "Add Description= to [Unit] section." }
func (r *BP008) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.unit.html#Description="}
}
func (r *BP008) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil {
		return nil
	}
	if unit.GetDirective("Unit", "Description") == "" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Unit has no Description.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// BP009 - Non-existent User/Group
type BP009 struct{}

func (r *BP009) ID() string               { return "BP009" }
func (r *BP009) Name() string             { return "User or Group may not exist" }
func (r *BP009) Description() string      { return "Specified User/Group should exist on the system." }
func (r *BP009) Category() types.Category { return types.CategoryBestPractice }
func (r *BP009) Severity() types.Severity { return types.SeverityHigh }
func (r *BP009) Tags() []string           { return []string{"user", "permissions"} }
func (r *BP009) Suggestion() string       { return "Ensure the user/group exists or use DynamicUser=yes." }
func (r *BP009) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#User="}
}
func (r *BP009) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	userName := unit.GetDirective("Service", "User")
	if userName != "" && userName != "root" {
		if _, err := user.Lookup(userName); err != nil {
			return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "User '" + userName + "' may not exist.", Suggestion: r.Suggestion(), References: r.References()}}
		}
	}
	return nil
}

// BP010 - Type=oneshot without RemainAfterExit
type BP010 struct{}

func (r *BP010) ID() string   { return "BP010" }
func (r *BP010) Name() string { return "Type=oneshot without RemainAfterExit" }
func (r *BP010) Description() string {
	return "Oneshot services may need RemainAfterExit for dependency tracking."
}
func (r *BP010) Category() types.Category { return types.CategoryBestPractice }
func (r *BP010) Severity() types.Severity { return types.SeverityLow }
func (r *BP010) Tags() []string           { return []string{"oneshot"} }
func (r *BP010) Suggestion() string       { return "Consider adding RemainAfterExit=yes." }
func (r *BP010) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#RemainAfterExit="}
}
func (r *BP010) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if unit.GetDirective("Service", "Type") == "oneshot" {
		if unit.GetDirective("Service", "RemainAfterExit") == "" {
			return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Oneshot service without RemainAfterExit.", Suggestion: r.Suggestion(), References: r.References()}}
		}
	}
	return nil
}
