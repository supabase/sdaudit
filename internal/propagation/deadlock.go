package propagation

import (
	"fmt"
	"sort"

	"github.com/supabase/sdaudit/internal/graph"
	"github.com/supabase/sdaudit/pkg/types"
)

// RestartDeadlock represents a scenario where units cannot restart properly.
type RestartDeadlock struct {
	UnitA      string       // Unit A has After=B and BindsTo=B
	UnitB      string       // Unit B depends on A somehow
	Scenario   string       // Description of the deadlock
	Severity   string       // "critical", "high", "medium"
	Edges      []graph.Edge // Edges involved
	Resolution string       // Suggested fix
}

// DeadlockResult contains all detected deadlocks.
type DeadlockResult struct {
	Deadlocks      []RestartDeadlock
	TotalDeadlocks int
	CriticalCount  int
	HighCount      int
}

// DetectDeadlocks finds patterns that can cause restart deadlocks.
//
// Pattern 1: A has After=B and BindsTo=B. If B restarts:
//   - A stops (due to BindsTo)
//   - A can't restart until B is active (due to After)
//   - If B also needs A, deadlock
//
// Pattern 2: Circular After= dependencies where units can't determine start order
//
// Pattern 3: BindsTo + Conflicts creating impossible states
func DetectDeadlocks(g *graph.Graph, units map[string]*types.UnitFile) DeadlockResult {
	var deadlocks []RestartDeadlock

	// Build lookup maps
	afterDeps := make(map[string]map[string]bool)    // unit -> units it must start after
	bindsToDeps := make(map[string]map[string]bool)  // unit -> units it's bound to
	requiresDeps := make(map[string]map[string]bool) // unit -> units it requires

	for _, edge := range g.Edges() {
		switch edge.Type {
		case graph.EdgeAfter:
			if afterDeps[edge.From] == nil {
				afterDeps[edge.From] = make(map[string]bool)
			}
			afterDeps[edge.From][edge.To] = true

		case graph.EdgeBindsTo:
			if bindsToDeps[edge.From] == nil {
				bindsToDeps[edge.From] = make(map[string]bool)
			}
			bindsToDeps[edge.From][edge.To] = true

		case graph.EdgeRequires:
			if requiresDeps[edge.From] == nil {
				requiresDeps[edge.From] = make(map[string]bool)
			}
			requiresDeps[edge.From][edge.To] = true
		}
	}

	// Pattern 1: After + BindsTo deadlock
	// A has After=B and BindsTo=B
	// If B also depends on A (via Requires, After, etc.), potential deadlock
	for unitA, boundTo := range bindsToDeps {
		for unitB := range boundTo {
			// Check if A also has After=B
			if afterDeps[unitA] != nil && afterDeps[unitA][unitB] {
				// A has both BindsTo=B and After=B
				// Check if B has any dependency on A

				// Direct Requires
				if requiresDeps[unitB] != nil && requiresDeps[unitB][unitA] {
					deadlocks = append(deadlocks, RestartDeadlock{
						UnitA: unitA,
						UnitB: unitB,
						Scenario: fmt.Sprintf(
							"%s has After=%s and BindsTo=%s. "+
								"%s has Requires=%s. "+
								"If %s restarts: %s stops (BindsTo), "+
								"%s can't restart until %s is active (After), "+
								"but %s needs %s (Requires). Potential deadlock.",
							unitA, unitB, unitB,
							unitB, unitA,
							unitB, unitA,
							unitA, unitB,
							unitB, unitA),
						Severity:   "critical",
						Resolution: "Remove circular dependency or change BindsTo to Requires",
					})
				}

				// Direct After (ordering deadlock)
				if afterDeps[unitB] != nil && afterDeps[unitB][unitA] {
					deadlocks = append(deadlocks, RestartDeadlock{
						UnitA: unitA,
						UnitB: unitB,
						Scenario: fmt.Sprintf(
							"%s has After=%s and BindsTo=%s. "+
								"%s has After=%s. "+
								"Mutual After= creates ordering deadlock on restart.",
							unitA, unitB, unitB,
							unitB, unitA),
						Severity:   "high",
						Resolution: "Break the circular After= dependency",
					})
				}

				// BindsTo in both directions
				if bindsToDeps[unitB] != nil && bindsToDeps[unitB][unitA] {
					deadlocks = append(deadlocks, RestartDeadlock{
						UnitA: unitA,
						UnitB: unitB,
						Scenario: fmt.Sprintf(
							"Mutual BindsTo between %s and %s with After= ordering. "+
								"If either stops, both stop and may not restart correctly.",
							unitA, unitB),
						Severity:   "critical",
						Resolution: "Use Requires instead of BindsTo for one direction",
					})
				}
			}
		}
	}

	// Pattern 2: Transitive deadlock through third unit
	// A BindsTo B, B After C, C Requires A
	for unitA, boundTo := range bindsToDeps {
		for unitB := range boundTo {
			// Find units that B must start after
			if afterDeps[unitB] == nil {
				continue
			}
			for unitC := range afterDeps[unitB] {
				if unitC == unitA {
					continue
				}
				// Check if C requires A
				if requiresDeps[unitC] != nil && requiresDeps[unitC][unitA] {
					deadlocks = append(deadlocks, RestartDeadlock{
						UnitA: unitA,
						UnitB: unitB,
						Scenario: fmt.Sprintf(
							"Transitive deadlock: %s BindsTo %s, %s After %s, %s Requires %s. "+
								"If %s stops, %s stops. %s can't start until %s which needs %s.",
							unitA, unitB, unitB, unitC, unitC, unitA,
							unitB, unitA, unitB, unitC, unitA),
						Severity:   "high",
						Resolution: "Simplify the dependency chain",
					})
				}
			}
		}
	}

	// Pattern 3: BindsTo + Conflicts
	// A BindsTo B, A Conflicts C, B Requires C -> impossible state
	conflictsDeps := make(map[string]map[string]bool)
	for _, edge := range g.Edges() {
		if edge.Type == graph.EdgeConflicts {
			if conflictsDeps[edge.From] == nil {
				conflictsDeps[edge.From] = make(map[string]bool)
			}
			conflictsDeps[edge.From][edge.To] = true
		}
	}

	for unitA, boundTo := range bindsToDeps {
		for unitB := range boundTo {
			// Check if A conflicts with something B requires
			if conflictsDeps[unitA] == nil {
				continue
			}
			if requiresDeps[unitB] == nil {
				continue
			}

			for conflictUnit := range conflictsDeps[unitA] {
				if requiresDeps[unitB][conflictUnit] {
					deadlocks = append(deadlocks, RestartDeadlock{
						UnitA: unitA,
						UnitB: unitB,
						Scenario: fmt.Sprintf(
							"%s BindsTo %s, but %s Conflicts with %s which %s Requires. "+
								"This creates an impossible state.",
							unitA, unitB, unitA, conflictUnit, unitB),
						Severity:   "critical",
						Resolution: "Remove the conflicting dependency",
					})
				}
			}
		}
	}

	// Sort by severity
	sort.Slice(deadlocks, func(i, j int) bool {
		return severityOrder(deadlocks[i].Severity) < severityOrder(deadlocks[j].Severity)
	})

	// Deduplicate (A-B and B-A are the same deadlock)
	seen := make(map[string]bool)
	var unique []RestartDeadlock
	for _, d := range deadlocks {
		key := d.UnitA + ":" + d.UnitB
		if d.UnitB < d.UnitA {
			key = d.UnitB + ":" + d.UnitA
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, d)
		}
	}
	deadlocks = unique

	// Build result
	result := DeadlockResult{
		Deadlocks:      deadlocks,
		TotalDeadlocks: len(deadlocks),
	}
	for _, d := range deadlocks {
		switch d.Severity {
		case "critical":
			result.CriticalCount++
		case "high":
			result.HighCount++
		}
	}

	return result
}

// TimeoutDeadlock represents a scenario where job timeouts cause issues.
type TimeoutDeadlock struct {
	Unit        string
	Description string
	Severity    string
}

// DetectTimeoutDeadlocks finds scenarios where job-level timeouts
// can cause unexpected behavior during dependency resolution.
//
// Job timeout starts at transaction begin, but unit's start timeout
// starts when it actually begins activating. Long dependency chains
// can cause jobs to timeout waiting.
func DetectTimeoutDeadlocks(g *graph.Graph, units map[string]*types.UnitFile) []TimeoutDeadlock {
	var deadlocks []TimeoutDeadlock

	for name, unit := range units {
		if unit == nil {
			continue
		}

		// Check for JobTimeoutSec with long dependency chains
		jobTimeout := unit.GetDirective("Unit", "JobTimeoutSec")
		if jobTimeout == "" {
			continue
		}

		// Count After= dependencies
		afterCount := 0
		for _, edge := range g.EdgesFrom(name) {
			if edge.Type == graph.EdgeAfter {
				afterCount++
			}
		}

		// Get transitive dependency count
		transDeps := g.TransitiveDependencies(name)

		if len(transDeps) > 10 && afterCount > 3 {
			deadlocks = append(deadlocks, TimeoutDeadlock{
				Unit: name,
				Description: fmt.Sprintf(
					"%s has JobTimeoutSec=%s but %d transitive dependencies (%d direct After=). "+
						"Job timeout starts at transaction begin, so waiting for dependencies "+
						"consumes the timeout budget.",
					name, jobTimeout, len(transDeps), afterCount),
				Severity: "medium",
			})
		}
	}

	return deadlocks
}

// WaitDeadlock represents units that might wait indefinitely.
type WaitDeadlock struct {
	Unit     string
	WaitsFor string
	Reason   string
	Severity string
}

// DetectWaitDeadlocks finds scenarios where units might wait indefinitely.
func DetectWaitDeadlocks(g *graph.Graph, units map[string]*types.UnitFile) []WaitDeadlock {
	var deadlocks []WaitDeadlock

	// Find units with Requisite= to potentially inactive units
	for _, edge := range g.Edges() {
		if edge.Type != graph.EdgeRequisite {
			continue
		}

		// Requisite requires the unit to already be active
		// If the requisite unit has ConditionXXX that might fail,
		// the dependent will never start
		reqUnit, ok := units[edge.To]
		if !ok || reqUnit == nil {
			// Requisite to missing unit - will always fail
			deadlocks = append(deadlocks, WaitDeadlock{
				Unit:     edge.From,
				WaitsFor: edge.To,
				Reason: fmt.Sprintf(
					"%s has Requisite=%s but %s doesn't exist. "+
						"%s will never start.",
					edge.From, edge.To, edge.To, edge.From),
				Severity: "critical",
			})
			continue
		}

		// Check for conditions that might prevent activation
		if unitSection, ok := reqUnit.Sections["Unit"]; ok {
			for key := range unitSection.Directives {
				if len(key) > 9 && key[:9] == "Condition" {
					deadlocks = append(deadlocks, WaitDeadlock{
						Unit:     edge.From,
						WaitsFor: edge.To,
						Reason: fmt.Sprintf(
							"%s has Requisite=%s, but %s has %s conditions. "+
								"If conditions fail, %s cannot start.",
							edge.From, edge.To, edge.To, key, edge.From),
						Severity: "medium",
					})
					break
				}
			}
		}
	}

	return deadlocks
}
