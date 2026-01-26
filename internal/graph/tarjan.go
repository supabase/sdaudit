package graph

import (
	"sort"

	"gonum.org/v1/gonum/graph/topo"
)

// SCC represents a strongly connected component (a cycle if len > 1).
type SCC struct {
	Units     []string   // Units in the cycle (sorted for determinism)
	Edges     []Edge     // Edges forming the cycle
	EdgeTypes []EdgeType // Which relationship types are involved
}

// FindCycles returns all non-trivial SCCs (cycles) in the graph.
// A cycle exists when len(SCC.Units) > 1.
// Uses Tarjan's algorithm via gonum - O(V+E) complexity.
func (g *Graph) FindCycles() []SCC {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Use gonum's Tarjan SCC implementation
	sccs := topo.TarjanSCC(g.g)

	var cycles []SCC
	for _, scc := range sccs {
		// Only interested in non-trivial SCCs (more than one node)
		if len(scc) <= 1 {
			continue
		}

		// Convert gonum nodes to unit names
		unitNames := make([]string, 0, len(scc))
		unitSet := make(map[string]bool)
		for _, node := range scc {
			name, ok := g.nodes[node.ID()]
			if ok {
				unitNames = append(unitNames, name)
				unitSet[name] = true
			}
		}

		// Sort for determinism
		sort.Strings(unitNames)

		// Find edges within this SCC
		var cycleEdges []Edge
		edgeTypeSet := make(map[EdgeType]bool)
		for _, edge := range g.allEdges {
			if unitSet[edge.From] && unitSet[edge.To] {
				cycleEdges = append(cycleEdges, edge)
				edgeTypeSet[edge.Type] = true
			}
		}

		// Collect unique edge types
		var edgeTypes []EdgeType
		for et := range edgeTypeSet {
			edgeTypes = append(edgeTypes, et)
		}
		// Sort edge types for determinism
		sort.Slice(edgeTypes, func(i, j int) bool {
			return edgeTypes[i] < edgeTypes[j]
		})

		cycles = append(cycles, SCC{
			Units:     unitNames,
			Edges:     cycleEdges,
			EdgeTypes: edgeTypes,
		})
	}

	// Sort cycles by first unit name for determinism
	sort.Slice(cycles, func(i, j int) bool {
		if len(cycles[i].Units) == 0 {
			return true
		}
		if len(cycles[j].Units) == 0 {
			return false
		}
		return cycles[i].Units[0] < cycles[j].Units[0]
	})

	return cycles
}

// HasCycles returns true if the graph contains any cycles.
func (g *Graph) HasCycles() bool {
	return len(g.FindCycles()) > 0
}

// CycleDescription returns a human-readable description of a cycle.
func (s SCC) CycleDescription() string {
	if len(s.Units) == 0 {
		return "empty cycle"
	}

	desc := s.Units[0]
	for i := 1; i < len(s.Units); i++ {
		desc += " -> " + s.Units[i]
	}
	desc += " -> " + s.Units[0]
	return desc
}

// InvolvedEdgeTypes returns a string describing the edge types in the cycle.
func (s SCC) InvolvedEdgeTypes() string {
	if len(s.EdgeTypes) == 0 {
		return "none"
	}

	desc := s.EdgeTypes[0].String()
	for i := 1; i < len(s.EdgeTypes); i++ {
		desc += ", " + s.EdgeTypes[i].String()
	}
	return desc
}

// FindCyclesInvolving returns cycles that include a specific unit.
func (g *Graph) FindCyclesInvolving(unit string) []SCC {
	allCycles := g.FindCycles()
	var matching []SCC

	for _, cycle := range allCycles {
		for _, u := range cycle.Units {
			if u == unit {
				matching = append(matching, cycle)
				break
			}
		}
	}

	return matching
}

// CycleSeverity returns the severity of a cycle based on edge types involved.
// Cycles involving Requires/BindsTo/Requisite are more severe.
func (s SCC) CycleSeverity() string {
	for _, et := range s.EdgeTypes {
		if et == EdgeRequires || et == EdgeBindsTo || et == EdgeRequisite {
			return "critical"
		}
	}

	for _, et := range s.EdgeTypes {
		if et == EdgeWants {
			return "high"
		}
	}

	return "medium"
}
