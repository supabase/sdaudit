package propagation

import (
	"fmt"
	"sort"

	"github.com/supabase/sdaudit/internal/graph"
	"github.com/supabase/sdaudit/pkg/types"
)

// RestartStorm represents a potential cascading restart scenario.
type RestartStorm struct {
	Units       []string // Units involved in the storm
	Trigger     string   // Initial failure point
	Cycle       []string // If cyclic, the cycle path
	Severity    string   // "critical", "high", "medium"
	Description string
	Evidence    []StormEdge // Edges causing propagation
}

// StormEdge describes an edge contributing to a restart storm.
type StormEdge struct {
	From   string
	To     string
	Type   graph.EdgeType
	Reason string // "BindsTo triggers stop", "Restart=on-failure restarts"
}

// RestartStormResult contains all detected restart storms.
type RestartStormResult struct {
	Storms        []RestartStorm
	TotalStorms   int
	CriticalCount int
	HighCount     int
	MediumCount   int
}

// DetectRestartStorms finds BindsTo= + Restart=on-failure cycles
// where failure of one unit triggers cascading restarts.
func DetectRestartStorms(g *graph.Graph, units map[string]*types.UnitFile) RestartStormResult {
	var storms []RestartStorm

	// Find units with Restart= policy
	restartUnits := make(map[string]string) // unit -> restart policy
	for name, unit := range units {
		if unit == nil || unit.Type != "service" {
			continue
		}
		policy := unit.GetDirective("Service", "Restart")
		if policy != "" && policy != "no" {
			restartUnits[name] = policy
		}
	}

	// Find BindsTo= relationships
	bindsTo := make(map[string][]string) // unit -> units it's bound to
	boundBy := make(map[string][]string) // unit -> units bound to it

	for _, edge := range g.Edges() {
		if edge.Type == graph.EdgeBindsTo {
			bindsTo[edge.From] = append(bindsTo[edge.From], edge.To)
			boundBy[edge.To] = append(boundBy[edge.To], edge.From)
		}
	}

	// Detect storm patterns

	// Pattern 1: Mutual BindsTo with Restart
	// A BindsTo B and B BindsTo A, both have Restart=
	checked := make(map[string]bool)
	for unitA, boundToList := range bindsTo {
		for _, unitB := range boundToList {
			// Check if B also binds to A
			for _, boundBack := range bindsTo[unitB] {
				if boundBack == unitA {
					key := unitA + ":" + unitB
					if unitB < unitA {
						key = unitB + ":" + unitA
					}
					if checked[key] {
						continue
					}
					checked[key] = true

					// Both have BindsTo to each other
					hasRestartA := restartUnits[unitA] != ""
					hasRestartB := restartUnits[unitB] != ""

					if hasRestartA || hasRestartB {
						severity := "high"
						if hasRestartA && hasRestartB {
							severity = "critical"
						}

						storm := RestartStorm{
							Units:    []string{unitA, unitB},
							Trigger:  unitA,
							Cycle:    []string{unitA, unitB, unitA},
							Severity: severity,
							Description: fmt.Sprintf(
								"Mutual BindsTo between %s and %s with Restart= enabled. "+
									"If either fails, both will stop and attempt to restart, "+
									"potentially causing a restart loop.",
								unitA, unitB),
							Evidence: []StormEdge{
								{From: unitA, To: unitB, Type: graph.EdgeBindsTo, Reason: "BindsTo triggers stop on failure"},
								{From: unitB, To: unitA, Type: graph.EdgeBindsTo, Reason: "BindsTo triggers stop on failure"},
							},
						}

						if hasRestartA {
							storm.Evidence = append(storm.Evidence, StormEdge{
								From:   unitA,
								To:     unitA,
								Type:   graph.EdgeRequires, // Placeholder
								Reason: fmt.Sprintf("Restart=%s causes restart on failure", restartUnits[unitA]),
							})
						}
						if hasRestartB {
							storm.Evidence = append(storm.Evidence, StormEdge{
								From:   unitB,
								To:     unitB,
								Type:   graph.EdgeRequires,
								Reason: fmt.Sprintf("Restart=%s causes restart on failure", restartUnits[unitB]),
							})
						}

						storms = append(storms, storm)
					}
				}
			}
		}
	}

	// Pattern 2: BindsTo chain with Restart forming a cycle
	// A BindsTo B, B BindsTo C, C has something that triggers A
	cycles := g.FindCycles()
	for _, scc := range cycles {
		// Check if cycle involves BindsTo and Restart
		hasBindsTo := false
		hasRestart := false
		var restartUnitsInCycle []string

		for _, et := range scc.EdgeTypes {
			if et == graph.EdgeBindsTo {
				hasBindsTo = true
			}
		}

		for _, unit := range scc.Units {
			if restartUnits[unit] != "" {
				hasRestart = true
				restartUnitsInCycle = append(restartUnitsInCycle, unit)
			}
		}

		if hasBindsTo && hasRestart {
			severity := "high"
			if len(restartUnitsInCycle) > 1 {
				severity = "critical"
			}

			var evidence []StormEdge
			for _, edge := range scc.Edges {
				if edge.Type == graph.EdgeBindsTo {
					evidence = append(evidence, StormEdge{
						From:   edge.From,
						To:     edge.To,
						Type:   edge.Type,
						Reason: "BindsTo propagates stop",
					})
				}
			}

			storms = append(storms, RestartStorm{
				Units:    scc.Units,
				Trigger:  scc.Units[0],
				Cycle:    append(scc.Units, scc.Units[0]),
				Severity: severity,
				Description: fmt.Sprintf(
					"Dependency cycle involving %d units with BindsTo and Restart=. "+
						"Units: %v. A failure in this cycle could cause cascading restarts.",
					len(scc.Units), scc.Units),
				Evidence: evidence,
			})
		}
	}

	// Pattern 3: BindsTo to unit with aggressive Restart
	// A BindsTo B, B has Restart=always with short RestartSec
	for unitA, boundToList := range bindsTo {
		for _, unitB := range boundToList {
			policy := restartUnits[unitB]
			if policy == "always" || policy == "on-failure" || policy == "on-abnormal" {
				// Check if A also has Restart
				policyA := restartUnits[unitA]
				if policyA != "" {
					// Already covered in mutual BindsTo check
					continue
				}

				// A depends on B via BindsTo, B restarts aggressively
				// This can cause A to be stopped and not restarted
				storms = append(storms, RestartStorm{
					Units:    []string{unitA, unitB},
					Trigger:  unitB,
					Severity: "medium",
					Description: fmt.Sprintf(
						"%s has BindsTo=%s, and %s has Restart=%s. "+
							"If %s fails and restarts, %s will be stopped but has no Restart= policy "+
							"to automatically recover.",
						unitA, unitB, unitB, policy, unitB, unitA),
					Evidence: []StormEdge{
						{From: unitA, To: unitB, Type: graph.EdgeBindsTo, Reason: "BindsTo causes stop when " + unitB + " stops"},
						{From: unitB, To: unitB, Type: graph.EdgeRequires, Reason: fmt.Sprintf("Restart=%s", policy)},
					},
				})
			}
		}
	}

	// Sort by severity
	sort.Slice(storms, func(i, j int) bool {
		return severityOrder(storms[i].Severity) < severityOrder(storms[j].Severity)
	})

	// Build result
	result := RestartStormResult{
		Storms:      storms,
		TotalStorms: len(storms),
	}
	for _, storm := range storms {
		switch storm.Severity {
		case "critical":
			result.CriticalCount++
		case "high":
			result.HighCount++
		case "medium":
			result.MediumCount++
		}
	}

	return result
}

func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

// AnalyzeRestartBehavior analyzes the restart configuration of a unit.
type RestartBehavior struct {
	Unit               string
	RestartPolicy      string
	RestartSec         string
	StartLimitBurst    string
	StartLimitInterval string
	HasBindsTo         bool
	BoundToUnits       []string
	BoundByUnits       []string
	StormRisk          string // "high", "medium", "low", "none"
	Description        string
}

// AnalyzeRestartBehavior provides detailed restart analysis for a unit.
func AnalyzeRestartBehavior(unitName string, g *graph.Graph, units map[string]*types.UnitFile) *RestartBehavior {
	unit, ok := units[unitName]
	if !ok || unit == nil {
		return nil
	}

	behavior := &RestartBehavior{
		Unit: unitName,
	}

	// Get restart configuration
	if unit.Type == "service" {
		behavior.RestartPolicy = unit.GetDirective("Service", "Restart")
		behavior.RestartSec = unit.GetDirective("Service", "RestartSec")
	}

	// Get rate limiting
	behavior.StartLimitBurst = unit.GetDirective("Unit", "StartLimitBurst")
	behavior.StartLimitInterval = unit.GetDirective("Unit", "StartLimitIntervalSec")
	if behavior.StartLimitInterval == "" {
		behavior.StartLimitInterval = unit.GetDirective("Unit", "StartLimitInterval")
	}

	// Find BindsTo relationships
	for _, edge := range g.EdgesFrom(unitName) {
		if edge.Type == graph.EdgeBindsTo {
			behavior.HasBindsTo = true
			behavior.BoundToUnits = append(behavior.BoundToUnits, edge.To)
		}
	}

	for _, edge := range g.EdgesTo(unitName) {
		if edge.Type == graph.EdgeBindsTo {
			behavior.BoundByUnits = append(behavior.BoundByUnits, edge.From)
		}
	}

	// Assess storm risk
	behavior.StormRisk = "none"
	if behavior.HasBindsTo && behavior.RestartPolicy != "" && behavior.RestartPolicy != "no" {
		behavior.StormRisk = "medium"
		if len(behavior.BoundByUnits) > 0 {
			behavior.StormRisk = "high"
		}
	}

	// Generate description
	if behavior.StormRisk != "none" {
		behavior.Description = fmt.Sprintf(
			"%s has Restart=%s with BindsTo dependencies. ",
			unitName, behavior.RestartPolicy)
		if len(behavior.BoundToUnits) > 0 {
			behavior.Description += fmt.Sprintf("Bound to: %v. ", behavior.BoundToUnits)
		}
		if len(behavior.BoundByUnits) > 0 {
			behavior.Description += fmt.Sprintf("Bound by: %v. ", behavior.BoundByUnits)
		}
		behavior.Description += "This could lead to restart cascades."
	}

	return behavior
}
