package performance

import (
	"strconv"
	"strings"

	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&PERF001{})
	rules.Register(&PERF002{})
	rules.Register(&PERF003{})
	rules.Register(&PERF004{})
	rules.Register(&PERF005{})
}

// PERF001 - Service in boot path not optimized
type PERF001 struct{}

func (r *PERF001) ID() string   { return "PERF001" }
func (r *PERF001) Name() string { return "Boot-critical service not optimized" }
func (r *PERF001) Description() string {
	return "Services in default target should consider socket activation."
}
func (r *PERF001) Category() types.Category { return types.CategoryPerformance }
func (r *PERF001) Severity() types.Severity { return types.SeverityLow }
func (r *PERF001) Tags() []string           { return []string{"boot", "socket-activation"} }
func (r *PERF001) Suggestion() string       { return "Consider socket activation for faster boot." }
func (r *PERF001) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.socket.html"}
}
func (r *PERF001) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	wantedBy := unit.GetDirective("Install", "WantedBy")
	if !strings.Contains(wantedBy, "multi-user.target") && !strings.Contains(wantedBy, "default.target") {
		return nil
	}
	// Check if there's a corresponding socket unit
	socketName := strings.TrimSuffix(unit.Name, ".service") + ".socket"
	if _, hasSocket := ctx.AllUnits[socketName]; hasSocket {
		return nil
	}
	serviceType := unit.GetDirective("Service", "Type")
	if serviceType == "oneshot" {
		return nil
	}
	return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Boot-path service could use socket activation.", Suggestion: r.Suggestion(), References: r.References()}}
}

// PERF002 - Excessive ExecStartPre
type PERF002 struct{}

func (r *PERF002) ID() string               { return "PERF002" }
func (r *PERF002) Name() string             { return "Excessive ExecStartPre commands" }
func (r *PERF002) Description() string      { return "Too many pre-start commands slow down service start." }
func (r *PERF002) Category() types.Category { return types.CategoryPerformance }
func (r *PERF002) Severity() types.Severity { return types.SeverityLow }
func (r *PERF002) Tags() []string           { return []string{"startup", "slow"} }
func (r *PERF002) Suggestion() string {
	return "Consolidate ExecStartPre commands or move to ExecStart script."
}
func (r *PERF002) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#ExecStartPre="}
}
func (r *PERF002) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	preCmds := unit.GetDirectives("Service", "ExecStartPre")
	if len(preCmds) > 3 {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "Service has " + strconv.Itoa(len(preCmds)) + " ExecStartPre commands.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

// PERF003 - Missing Type=notify for long-running
type PERF003 struct{}

func (r *PERF003) ID() string               { return "PERF003" }
func (r *PERF003) Name() string             { return "Consider Type=notify for readiness" }
func (r *PERF003) Description() string      { return "Services with startup time should use Type=notify." }
func (r *PERF003) Category() types.Category { return types.CategoryPerformance }
func (r *PERF003) Severity() types.Severity { return types.SeverityInfo }
func (r *PERF003) Tags() []string           { return []string{"startup", "notify"} }
func (r *PERF003) Suggestion() string       { return "Use Type=notify if service supports sd_notify." }
func (r *PERF003) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#Type="}
}
func (r *PERF003) Check(ctx *rules.Context) []types.Issue {
	// Advisory only - can't detect if app supports sd_notify
	return nil
}

// PERF004 - Type=simple when forking appropriate
type PERF004 struct{}

func (r *PERF004) ID() string   { return "PERF004" }
func (r *PERF004) Name() string { return "Type=simple may block dependencies" }
func (r *PERF004) Description() string {
	return "Type=simple marks ready immediately, which may be premature."
}
func (r *PERF004) Category() types.Category { return types.CategoryPerformance }
func (r *PERF004) Severity() types.Severity { return types.SeverityInfo }
func (r *PERF004) Tags() []string           { return []string{"startup", "type"} }
func (r *PERF004) Suggestion() string {
	return "Use Type=exec, notify, or forking if startup time matters."
}
func (r *PERF004) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#Type="}
}
func (r *PERF004) Check(ctx *rules.Context) []types.Issue {
	// Advisory only
	return nil
}

// PERF005 - TimeoutStartSec too long
type PERF005 struct{}

func (r *PERF005) ID() string               { return "PERF005" }
func (r *PERF005) Name() string             { return "TimeoutStartSec excessively long" }
func (r *PERF005) Description() string      { return "Very long start timeouts delay failure detection." }
func (r *PERF005) Category() types.Category { return types.CategoryPerformance }
func (r *PERF005) Severity() types.Severity { return types.SeverityLow }
func (r *PERF005) Tags() []string           { return []string{"timeout", "startup"} }
func (r *PERF005) Suggestion() string       { return "Reduce TimeoutStartSec to a reasonable value." }
func (r *PERF005) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#TimeoutStartSec="}
}
func (r *PERF005) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}
	timeout := unit.GetDirective("Service", "TimeoutStartSec")
	if timeout == "" || timeout == "infinity" {
		return nil
	}
	// Parse and check if > 5 minutes
	seconds := parseTime(timeout)
	if seconds > 300 {
		return []types.Issue{{RuleID: r.ID(), RuleName: r.Name(), Severity: r.Severity(), Category: r.Category(), Tags: r.Tags(), Unit: unit.Name, File: unit.Path, Description: "TimeoutStartSec=" + timeout + " is very long.", Suggestion: r.Suggestion(), References: r.References()}}
	}
	return nil
}

func parseTime(s string) float64 {
	s = strings.TrimSpace(s)
	multipliers := map[string]float64{"ms": 0.001, "s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600}
	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			if v, err := strconv.ParseFloat(strings.TrimSuffix(s, suffix), 64); err == nil {
				return v * mult
			}
		}
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return v
	}
	return 0
}
