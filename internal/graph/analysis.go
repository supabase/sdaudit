package graph

import (
	"fmt"
	"sort"
)

// DanglingRef represents a reference to a non-existent unit.
type DanglingRef struct {
	From     string   // Unit making the reference
	To       string   // Missing unit
	EdgeType EdgeType // Type of reference (Requires is worse than Wants)
	File     string
	Line     int
}

// FindDanglingRefs finds all references to units that don't exist.
// Classifies by edge type - Requires= to missing is worse than Wants= to missing.
func (g *Graph) FindDanglingRefs() []DanglingRef {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var dangling []DanglingRef

	for _, edge := range g.allEdges {
		// Check if target unit exists (has a parsed unit file, not just a node)
		if _, exists := g.units[edge.To]; !exists {
			dangling = append(dangling, DanglingRef{
				From:     edge.From,
				To:       edge.To,
				EdgeType: edge.Type,
				File:     edge.File,
				Line:     edge.Line,
			})
		}
	}

	// Sort for determinism: by severity (edge type), then by From, then by To
	sort.Slice(dangling, func(i, j int) bool {
		// Higher severity edge types first
		si := danglingRefSeverityOrder(dangling[i].EdgeType)
		sj := danglingRefSeverityOrder(dangling[j].EdgeType)
		if si != sj {
			return si < sj
		}
		if dangling[i].From != dangling[j].From {
			return dangling[i].From < dangling[j].From
		}
		return dangling[i].To < dangling[j].To
	})

	return dangling
}

// danglingRefSeverityOrder returns the severity order for a dangling reference.
// Lower values are more severe.
func danglingRefSeverityOrder(et EdgeType) int {
	switch et {
	case EdgeRequires, EdgeRequisite, EdgeBindsTo:
		return 0 // Most severe - hard dependencies
	case EdgeWants:
		return 1 // Medium - soft dependencies
	case EdgeAfter, EdgeBefore:
		return 2 // Lower - ordering only
	default:
		return 3
	}
}

// Severity returns the severity level of a dangling reference.
func (d DanglingRef) Severity() string {
	switch d.EdgeType {
	case EdgeRequires, EdgeRequisite, EdgeBindsTo:
		return "high"
	case EdgeWants:
		return "medium"
	case EdgeAfter, EdgeBefore:
		return "low"
	default:
		return "info"
	}
}

// OrderingIssue represents a potential ordering problem.
type OrderingIssue struct {
	Unit        string
	Related     string
	IssueType   string // "after_without_requires" or "requires_without_after"
	Description string
	File        string
	Line        int
}

// FindOrderingIssues detects ordering inconsistencies:
// - After= without Requires= or Wants= (ordering only honored if both happen to start)
// - Requires= without After= (parallel start, may or may not be intentional)
func (g *Graph) FindOrderingIssues() []OrderingIssue {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var issues []OrderingIssue

	// Build maps for quick lookup
	// Key: "from:to", Value: edge types present
	edgeIndex := make(map[string]map[EdgeType]Edge)
	for _, edge := range g.allEdges {
		key := edge.From + ":" + edge.To
		if edgeIndex[key] == nil {
			edgeIndex[key] = make(map[EdgeType]Edge)
		}
		edgeIndex[key][edge.Type] = edge
	}

	// Check for After= without Requires=/Wants=
	for _, edge := range g.allEdges {
		if edge.Type != EdgeAfter {
			continue
		}

		key := edge.From + ":" + edge.To
		edges := edgeIndex[key]

		// Check if there's a requirement edge too
		hasRequirement := false
		for et := range edges {
			if et.IsRequirementEdge() {
				hasRequirement = true
				break
			}
		}

		if !hasRequirement {
			issues = append(issues, OrderingIssue{
				Unit:      edge.From,
				Related:   edge.To,
				IssueType: "after_without_requires",
				Description: fmt.Sprintf("%s has After=%s but no Requires= or Wants=. "+
					"Ordering is only honored if both units happen to start.",
					edge.From, edge.To),
				File: edge.File,
				Line: edge.Line,
			})
		}
	}

	// Check for Requires= without After=
	for _, edge := range g.allEdges {
		if edge.Type != EdgeRequires && edge.Type != EdgeBindsTo {
			continue
		}

		key := edge.From + ":" + edge.To
		edges := edgeIndex[key]

		// Check if there's an After edge too
		_, hasAfter := edges[EdgeAfter]

		if !hasAfter {
			issues = append(issues, OrderingIssue{
				Unit:      edge.From,
				Related:   edge.To,
				IssueType: "requires_without_after",
				Description: fmt.Sprintf("%s has %s=%s but no After=. "+
					"Units will start in parallel, which may cause race conditions.",
					edge.From, edge.Type.String(), edge.To),
				File: edge.File,
				Line: edge.Line,
			})
		}
	}

	// Sort for determinism
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Unit != issues[j].Unit {
			return issues[i].Unit < issues[j].Unit
		}
		if issues[i].Related != issues[j].Related {
			return issues[i].Related < issues[j].Related
		}
		return issues[i].IssueType < issues[j].IssueType
	})

	return issues
}

// BindsToWithoutAfter returns units that have BindsTo= without After=.
// This is particularly dangerous as stop propagates immediately.
type BindingIssue struct {
	Unit        string
	BoundTo     string
	Description string
	File        string
	Line        int
}

// FindBindingIssues finds BindsTo= relationships without proper After= ordering.
func (g *Graph) FindBindingIssues() []BindingIssue {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var issues []BindingIssue

	// Build After= index
	afterIndex := make(map[string]map[string]bool) // from -> set of to
	for _, edge := range g.allEdges {
		if edge.Type == EdgeAfter {
			if afterIndex[edge.From] == nil {
				afterIndex[edge.From] = make(map[string]bool)
			}
			afterIndex[edge.From][edge.To] = true
		}
	}

	// Check BindsTo= edges
	for _, edge := range g.allEdges {
		if edge.Type != EdgeBindsTo {
			continue
		}

		// Check if there's a corresponding After=
		hasAfter := afterIndex[edge.From] != nil && afterIndex[edge.From][edge.To]

		if !hasAfter {
			issues = append(issues, BindingIssue{
				Unit:    edge.From,
				BoundTo: edge.To,
				Description: fmt.Sprintf("%s has BindsTo=%s without After=. "+
					"If %s stops or restarts, %s will stop immediately, "+
					"potentially violating stop ordering.",
					edge.From, edge.To, edge.To, edge.From),
				File: edge.File,
				Line: edge.Line,
			})
		}
	}

	// Sort for determinism
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Unit != issues[j].Unit {
			return issues[i].Unit < issues[j].Unit
		}
		return issues[i].BoundTo < issues[j].BoundTo
	})

	return issues
}

// ConflictingDependencies finds units that have both Requires= and Conflicts=
// to the same target, or other contradictory configurations.
type ConflictIssue struct {
	Unit     string
	Target   string
	Conflict string // Description of the conflict
	File     string
	Line     int
}

// FindConflictingDependencies detects contradictory dependency configurations.
func (g *Graph) FindConflictingDependencies() []ConflictIssue {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var issues []ConflictIssue

	// Build edge indexes by from unit
	fromIndex := make(map[string]map[string][]EdgeType) // from -> to -> []types
	for _, edge := range g.allEdges {
		if fromIndex[edge.From] == nil {
			fromIndex[edge.From] = make(map[string][]EdgeType)
		}
		fromIndex[edge.From][edge.To] = append(fromIndex[edge.From][edge.To], edge.Type)
	}

	// Check for contradictions
	for from, targets := range fromIndex {
		for to, types := range targets {
			hasRequirement := false
			hasConflict := false
			var conflictEdge Edge

			for _, et := range types {
				if et.IsRequirementEdge() {
					hasRequirement = true
				}
				if et == EdgeConflicts {
					hasConflict = true
				}
			}

			if hasRequirement && hasConflict {
				// Find the conflict edge for line info
				for _, edge := range g.allEdges {
					if edge.From == from && edge.To == to && edge.Type == EdgeConflicts {
						conflictEdge = edge
						break
					}
				}

				issues = append(issues, ConflictIssue{
					Unit:   from,
					Target: to,
					Conflict: fmt.Sprintf("%s has both a requirement (Requires/Wants/BindsTo) "+
						"and Conflicts= to %s. These are contradictory.",
						from, to),
					File: conflictEdge.File,
					Line: conflictEdge.Line,
				})
			}
		}
	}

	// Sort for determinism
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Unit != issues[j].Unit {
			return issues[i].Unit < issues[j].Unit
		}
		return issues[i].Target < issues[j].Target
	})

	return issues
}

// GraphStats returns statistics about the graph.
type GraphStats struct {
	TotalUnits    int
	TotalEdges    int
	TotalNodes    int // Includes placeholder nodes for dangling refs
	EdgesByType   map[EdgeType]int
	UnitsByType   map[string]int
	CycleCount    int
	DanglingCount int
}

// Stats returns statistics about the graph.
func (g *Graph) Stats() GraphStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := GraphStats{
		TotalUnits:  len(g.units),
		TotalEdges:  len(g.allEdges),
		TotalNodes:  len(g.nodeIDs),
		EdgesByType: make(map[EdgeType]int),
		UnitsByType: make(map[string]int),
	}

	for _, edge := range g.allEdges {
		stats.EdgesByType[edge.Type]++
	}

	for _, unit := range g.units {
		if unit != nil {
			stats.UnitsByType[unit.Type]++
		}
	}

	stats.CycleCount = len(g.FindCycles())
	stats.DanglingCount = len(g.FindDanglingRefs())

	return stats
}
