// Package propagation provides failure propagation analysis for systemd units.
package propagation

import (
	"github.com/supabase/sdaudit/internal/graph"
	"github.com/supabase/sdaudit/pkg/types"
)

// PropagationSemantics defines how each edge type propagates failures.
type PropagationSemantics struct {
	EdgeType       graph.EdgeType
	StartFailure   bool // Does start failure propagate?
	StopPropagates bool // Does stop propagate?
	Immediate      bool // Is propagation immediate (Requisite)?
	Description    string
}

// Semantics maps edge types to their propagation behavior.
// This matches systemd's actual behavior.
var Semantics = map[graph.EdgeType]PropagationSemantics{
	graph.EdgeRequires: {
		EdgeType:       graph.EdgeRequires,
		StartFailure:   true,
		StopPropagates: false,
		Immediate:      false,
		Description:    "Start failure propagates to dependent; stop does not propagate",
	},
	graph.EdgeRequisite: {
		EdgeType:       graph.EdgeRequisite,
		StartFailure:   true,
		StopPropagates: false,
		Immediate:      true,
		Description:    "Dependency must already be active; failure is immediate",
	},
	graph.EdgeBindsTo: {
		EdgeType:       graph.EdgeBindsTo,
		StartFailure:   true,
		StopPropagates: true,
		Immediate:      false,
		Description:    "Start failure propagates; stop also propagates (strongest binding)",
	},
	graph.EdgeWants: {
		EdgeType:       graph.EdgeWants,
		StartFailure:   false,
		StopPropagates: false,
		Immediate:      false,
		Description:    "Soft dependency; failures do not propagate",
	},
	graph.EdgePartOf: {
		EdgeType:       graph.EdgePartOf,
		StartFailure:   false,
		StopPropagates: true,
		Immediate:      false,
		Description:    "Stop propagates (for grouped services); start failure does not",
	},
	graph.EdgeConflicts: {
		EdgeType:       graph.EdgeConflicts,
		StartFailure:   false,
		StopPropagates: false, // Inverse behavior
		Immediate:      true,
		Description:    "Mutually exclusive; starting one stops the other",
	},
}

// GetSemantics returns the propagation semantics for an edge type.
func GetSemantics(et graph.EdgeType) PropagationSemantics {
	if sem, ok := Semantics[et]; ok {
		return sem
	}
	return PropagationSemantics{
		EdgeType:    et,
		Description: "No propagation defined",
	}
}

// FailureImpact represents the impact of a unit failing.
type FailureImpact struct {
	FailedUnit    string
	AffectedUnits []AffectedUnit
	TotalAffected int
	CriticalChain []string // Most severe propagation chain
}

// AffectedUnit represents a unit affected by a failure.
type AffectedUnit struct {
	Name            string
	Impact          string // "stop", "fail_to_start", "restart"
	PropagationPath []string
	EdgeType        graph.EdgeType
	Severity        string // "critical", "high", "medium", "low"
}

// SimulateFailure simulates what happens when a unit fails.
// Returns all units that would be affected and how.
func SimulateFailure(g *graph.Graph, failedUnit string) FailureImpact {
	impact := FailureImpact{
		FailedUnit: failedUnit,
	}

	visited := make(map[string]bool)
	var propagate func(unit string, path []string, impactType string)

	propagate = func(unit string, path []string, impactType string) {
		if visited[unit] {
			return
		}
		visited[unit] = true

		// Find units that depend on this one
		edges := g.EdgesTo(unit)
		for _, edge := range edges {
			sem := GetSemantics(edge.Type)
			dependent := edge.From

			newPath := append([]string{}, path...)
			newPath = append(newPath, dependent)

			var newImpact string
			shouldPropagate := false

			switch impactType {
			case "fail":
				if sem.StartFailure {
					newImpact = "fail_to_start"
					shouldPropagate = true
				}
			case "stop":
				if sem.StopPropagates {
					newImpact = "stop"
					shouldPropagate = true
				}
			}

			if shouldPropagate && !visited[dependent] {
				severity := "medium"
				if edge.Type == graph.EdgeBindsTo || edge.Type == graph.EdgeRequires {
					severity = "high"
				}
				if edge.Type == graph.EdgeRequisite {
					severity = "critical"
				}

				impact.AffectedUnits = append(impact.AffectedUnits, AffectedUnit{
					Name:            dependent,
					Impact:          newImpact,
					PropagationPath: newPath,
					EdgeType:        edge.Type,
					Severity:        severity,
				})

				propagate(dependent, newPath, newImpact)
			}
		}
	}

	// Simulate both failure and stop scenarios
	propagate(failedUnit, []string{failedUnit}, "fail")

	// Reset for stop propagation
	visited = make(map[string]bool)
	visited[failedUnit] = true
	propagate(failedUnit, []string{failedUnit}, "stop")

	impact.TotalAffected = len(impact.AffectedUnits)

	// Find critical chain (longest high-severity path)
	var longestCritical []string
	for _, affected := range impact.AffectedUnits {
		if affected.Severity == "critical" || affected.Severity == "high" {
			if len(affected.PropagationPath) > len(longestCritical) {
				longestCritical = affected.PropagationPath
			}
		}
	}
	impact.CriticalChain = longestCritical

	return impact
}

// SilentFailure represents a critical unit using weak dependencies.
type SilentFailure struct {
	Unit        string         // The critical unit
	DependedBy  string         // Unit that should require it
	EdgeType    graph.EdgeType // Wants= instead of Requires=
	Risk        string         // Severity
	Description string
	File        string
	Line        int
}

// DetectSilentFailures finds critical units pulled in via Wants= instead of Requires=.
// These failures go unnoticed because Wants= doesn't propagate failure.
func DetectSilentFailures(g *graph.Graph, criticalUnits []string) []SilentFailure {
	var failures []SilentFailure

	criticalSet := make(map[string]bool)
	for _, u := range criticalUnits {
		criticalSet[u] = true
	}

	// If no critical units specified, use common critical services
	if len(criticalUnits) == 0 {
		criticalSet = map[string]bool{
			"dbus.service":             true,
			"systemd-journald.service": true,
			"systemd-logind.service":   true,
			"networking.service":       true,
			"network.target":           true,
			"syslog.service":           true,
		}
	}

	for _, edge := range g.Edges() {
		// Only interested in Wants= edges to critical units
		if edge.Type != graph.EdgeWants {
			continue
		}

		if !criticalSet[edge.To] {
			continue
		}

		// Check if there's also a Requires= edge (which would be correct)
		hasRequires := false
		for _, e := range g.EdgesFrom(edge.From) {
			if e.To == edge.To && (e.Type == graph.EdgeRequires || e.Type == graph.EdgeBindsTo) {
				hasRequires = true
				break
			}
		}

		if hasRequires {
			continue // Already has proper dependency
		}

		failures = append(failures, SilentFailure{
			Unit:       edge.To,
			DependedBy: edge.From,
			EdgeType:   edge.Type,
			Risk:       "medium",
			Description: edge.From + " uses Wants=" + edge.To +
				" for a critical service. If " + edge.To + " fails, " +
				edge.From + " will not be notified. Consider using Requires=.",
			File: edge.File,
			Line: edge.Line,
		})
	}

	return failures
}

// StopOrderInversion represents a potential stop ordering issue.
type StopOrderInversion struct {
	Unit        string
	BoundTo     string
	Description string
	Severity    string
}

// DetectStopOrderInversions finds BindsTo= relationships that may cause
// stop ordering to be violated when the bound unit stops.
func DetectStopOrderInversions(g *graph.Graph) []StopOrderInversion {
	var inversions []StopOrderInversion

	// Find all BindsTo= edges
	for _, edge := range g.Edges() {
		if edge.Type != graph.EdgeBindsTo {
			continue
		}

		dependent := edge.From
		dependency := edge.To

		// Check if there's proper Before= ordering
		// When dependency stops, we want dependent to stop first
		// This means we need: dependency Before= dependent (from dependent's perspective: After=)
		hasAfter := false
		for _, e := range g.EdgesFrom(dependent) {
			if e.To == dependency && e.Type == graph.EdgeAfter {
				hasAfter = true
				break
			}
		}

		if !hasAfter {
			inversions = append(inversions, StopOrderInversion{
				Unit:    dependent,
				BoundTo: dependency,
				Description: dependent + " has BindsTo=" + dependency + " without After=. " +
					"When " + dependency + " stops, " + dependent + " will stop immediately, " +
					"potentially before its own stop ordering is honored.",
				Severity: "high",
			})
		}
	}

	return inversions
}

// AnalyzePropagation provides a complete propagation analysis.
type PropagationAnalysis struct {
	SilentFailures      []SilentFailure
	StopOrderInversions []StopOrderInversion
	HighRiskUnits       []string // Units that could cause widespread impact
}

// Analyze performs complete propagation analysis.
func Analyze(g *graph.Graph, units map[string]*types.UnitFile) PropagationAnalysis {
	analysis := PropagationAnalysis{}

	// Detect silent failures
	analysis.SilentFailures = DetectSilentFailures(g, nil)

	// Detect stop order inversions
	analysis.StopOrderInversions = DetectStopOrderInversions(g)

	// Find high-risk units (many dependents with strong binding)
	dependentCount := make(map[string]int)
	strongDependentCount := make(map[string]int)

	for _, edge := range g.Edges() {
		if edge.Type.IsRequirementEdge() {
			dependentCount[edge.To]++
			if edge.Type == graph.EdgeRequires || edge.Type == graph.EdgeBindsTo {
				strongDependentCount[edge.To]++
			}
		}
	}

	// Units with many strong dependents are high risk
	for unit, count := range strongDependentCount {
		if count >= 5 {
			analysis.HighRiskUnits = append(analysis.HighRiskUnits, unit)
		}
	}

	return analysis
}
