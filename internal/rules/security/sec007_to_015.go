package security

import (
	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func init() {
	rules.Register(&SEC007{})
	rules.Register(&SEC008{})
	rules.Register(&SEC009{})
	rules.Register(&SEC010{})
	rules.Register(&SEC011{})
	rules.Register(&SEC012{})
	rules.Register(&SEC013{})
	rules.Register(&SEC014{})
	rules.Register(&SEC015{})
}

// SEC007 - PrivateDevices
type SEC007 struct{}

func (r *SEC007) ID() string               { return "SEC007" }
func (r *SEC007) Name() string             { return "PrivateDevices not set" }
func (r *SEC007) Description() string      { return "Services should use PrivateDevices=yes." }
func (r *SEC007) Category() types.Category { return types.CategorySecurity }
func (r *SEC007) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC007) Tags() []string           { return []string{"hardening", "isolation"} }
func (r *SEC007) Suggestion() string       { return "Add 'PrivateDevices=yes' to [Service]." }
func (r *SEC007) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#PrivateDevices="}
}
func (r *SEC007) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "PrivateDevices"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service has access to physical devices.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC008 - ProtectKernelTunables
type SEC008 struct{}

func (r *SEC008) ID() string               { return "SEC008" }
func (r *SEC008) Name() string             { return "ProtectKernelTunables not enabled" }
func (r *SEC008) Description() string      { return "Services should protect kernel tunables." }
func (r *SEC008) Category() types.Category { return types.CategorySecurity }
func (r *SEC008) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC008) Tags() []string           { return []string{"hardening", "kernel"} }
func (r *SEC008) Suggestion() string       { return "Add 'ProtectKernelTunables=yes' to [Service]." }
func (r *SEC008) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelTunables="}
}
func (r *SEC008) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "ProtectKernelTunables"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service can modify kernel tunables.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC009 - ProtectKernelModules
type SEC009 struct{}

func (r *SEC009) ID() string               { return "SEC009" }
func (r *SEC009) Name() string             { return "ProtectKernelModules not enabled" }
func (r *SEC009) Description() string      { return "Services should not load kernel modules." }
func (r *SEC009) Category() types.Category { return types.CategorySecurity }
func (r *SEC009) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC009) Tags() []string           { return []string{"hardening", "kernel"} }
func (r *SEC009) Suggestion() string       { return "Add 'ProtectKernelModules=yes' to [Service]." }
func (r *SEC009) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectKernelModules="}
}
func (r *SEC009) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "ProtectKernelModules"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service can load kernel modules.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC010 - ProtectControlGroups
type SEC010 struct{}

func (r *SEC010) ID() string               { return "SEC010" }
func (r *SEC010) Name() string             { return "ProtectControlGroups not enabled" }
func (r *SEC010) Description() string      { return "Services should protect cgroup hierarchy." }
func (r *SEC010) Category() types.Category { return types.CategorySecurity }
func (r *SEC010) Severity() types.Severity { return types.SeverityLow }
func (r *SEC010) Tags() []string           { return []string{"hardening", "cgroups"} }
func (r *SEC010) Suggestion() string       { return "Add 'ProtectControlGroups=yes' to [Service]." }
func (r *SEC010) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#ProtectControlGroups="}
}
func (r *SEC010) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "ProtectControlGroups"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service can modify control groups.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC011 - RestrictSUIDSGID
type SEC011 struct{}

func (r *SEC011) ID() string               { return "SEC011" }
func (r *SEC011) Name() string             { return "RestrictSUIDSGID not set" }
func (r *SEC011) Description() string      { return "Services should restrict SUID/SGID file creation." }
func (r *SEC011) Category() types.Category { return types.CategorySecurity }
func (r *SEC011) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC011) Tags() []string           { return []string{"hardening", "suid"} }
func (r *SEC011) Suggestion() string       { return "Add 'RestrictSUIDSGID=yes' to [Service]." }
func (r *SEC011) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictSUIDSGID="}
}
func (r *SEC011) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "RestrictSUIDSGID"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service can create SUID/SGID files.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC012 - RestrictNamespaces
type SEC012 struct{}

func (r *SEC012) ID() string               { return "SEC012" }
func (r *SEC012) Name() string             { return "RestrictNamespaces not configured" }
func (r *SEC012) Description() string      { return "Services should restrict namespace creation." }
func (r *SEC012) Category() types.Category { return types.CategorySecurity }
func (r *SEC012) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC012) Tags() []string           { return []string{"hardening", "namespaces"} }
func (r *SEC012) Suggestion() string       { return "Add 'RestrictNamespaces=yes' to [Service]." }
func (r *SEC012) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RestrictNamespaces="}
}
func (r *SEC012) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "RestrictNamespaces"); v == "" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service can create new namespaces.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC013 - SystemCallFilter
type SEC013 struct{}

func (r *SEC013) ID() string               { return "SEC013" }
func (r *SEC013) Name() string             { return "SystemCallFilter not configured" }
func (r *SEC013) Description() string      { return "Services should filter system calls." }
func (r *SEC013) Category() types.Category { return types.CategorySecurity }
func (r *SEC013) Severity() types.Severity { return types.SeverityHigh }
func (r *SEC013) Tags() []string           { return []string{"hardening", "seccomp", "syscalls"} }
func (r *SEC013) Suggestion() string {
	return "Add 'SystemCallFilter=@system-service' or specific filter to [Service]."
}
func (r *SEC013) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter="}
}
func (r *SEC013) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "SystemCallFilter"); v == "" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service has no syscall filtering (seccomp).", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC014 - MemoryDenyWriteExecute
type SEC014 struct{}

func (r *SEC014) ID() string               { return "SEC014" }
func (r *SEC014) Name() string             { return "MemoryDenyWriteExecute not set" }
func (r *SEC014) Description() string      { return "Services should prevent W^X memory mappings." }
func (r *SEC014) Category() types.Category { return types.CategorySecurity }
func (r *SEC014) Severity() types.Severity { return types.SeverityMedium }
func (r *SEC014) Tags() []string           { return []string{"hardening", "memory"} }
func (r *SEC014) Suggestion() string       { return "Add 'MemoryDenyWriteExecute=yes' to [Service]." }
func (r *SEC014) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#MemoryDenyWriteExecute="}
}
func (r *SEC014) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "MemoryDenyWriteExecute"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service allows writable-executable memory.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// SEC015 - LockPersonality
type SEC015 struct{}

func (r *SEC015) ID() string               { return "SEC015" }
func (r *SEC015) Name() string             { return "LockPersonality not set" }
func (r *SEC015) Description() string      { return "Services should lock execution personality." }
func (r *SEC015) Category() types.Category { return types.CategorySecurity }
func (r *SEC015) Severity() types.Severity { return types.SeverityLow }
func (r *SEC015) Tags() []string           { return []string{"hardening"} }
func (r *SEC015) Suggestion() string       { return "Add 'LockPersonality=yes' to [Service]." }
func (r *SEC015) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.exec.html#LockPersonality="}
}
func (r *SEC015) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	if v := unit.GetDirective("Service", "LockPersonality"); v == "" || v == "no" {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service execution personality not locked.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}
