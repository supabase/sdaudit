package graph

import (
	"sort"
	"strings"
)

// ReachabilityResult contains units categorized by reachability.
type ReachabilityResult struct {
	Reachable   []string // Units reachable from targets
	Unreachable []string // Potentially dead units
	Targets     []string // .target units used as roots
}

// AnalyzeReachability walks backward from default.target and other targets.
// Reports units that are never pulled in by any target.
// This identifies potentially dead or orphaned units.
func (g *Graph) AnalyzeReachability() ReachabilityResult {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Find all target units to use as roots
	var targets []string
	for name, unit := range g.units {
		if unit != nil && unit.Type == "target" {
			targets = append(targets, name)
		}
	}

	// Also include default.target if it exists as a node but not a unit
	for name := range g.nodeIDs {
		if strings.HasSuffix(name, ".target") {
			found := false
			for _, t := range targets {
				if t == name {
					found = true
					break
				}
			}
			if !found {
				targets = append(targets, name)
			}
		}
	}

	sort.Strings(targets)

	// BFS backward from all targets
	visited := make(map[string]bool)
	queue := make([]string, 0, len(targets))

	// Start with all targets
	for _, t := range targets {
		if !visited[t] {
			visited[t] = true
			queue = append(queue, t)
		}
	}

	// Walk backward through dependency edges
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Find all edges pointing TO this unit (dependencies of this unit)
		for _, edge := range g.incoming[current] {
			// Only follow requirement edges backward (these pull units in)
			if edge.Type.IsRequirementEdge() || edge.Type == EdgeTriggeredBy {
				if !visited[edge.From] {
					visited[edge.From] = true
					queue = append(queue, edge.From)
				}
			}
		}

		// Also follow WantedBy/RequiredBy relationships (outgoing edges from targets)
		for _, edge := range g.outgoing[current] {
			if edge.Type.IsRequirementEdge() || edge.Type == EdgeTriggeredBy {
				if !visited[edge.To] {
					visited[edge.To] = true
					queue = append(queue, edge.To)
				}
			}
		}
	}

	// Categorize units
	var reachable, unreachable []string
	for name := range g.units {
		if visited[name] {
			reachable = append(reachable, name)
		} else {
			unreachable = append(unreachable, name)
		}
	}

	sort.Strings(reachable)
	sort.Strings(unreachable)

	return ReachabilityResult{
		Reachable:   reachable,
		Unreachable: unreachable,
		Targets:     targets,
	}
}

// IsReachable returns true if a unit is reachable from any target.
func (g *Graph) IsReachable(unit string) bool {
	result := g.AnalyzeReachability()
	for _, u := range result.Reachable {
		if u == unit {
			return true
		}
	}
	return false
}

// UnreachableUnits returns a list of units not reachable from any target.
func (g *Graph) UnreachableUnits() []string {
	return g.AnalyzeReachability().Unreachable
}

// ReachableFrom returns all units reachable from a specific starting unit.
// Direction can be "forward" (what does this unit depend on) or
// "backward" (what depends on this unit).
func (g *Graph) ReachableFrom(unit string, direction string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	visited := make(map[string]bool)
	queue := []string{unit}
	visited[unit] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		var edges []Edge
		if direction == "forward" {
			edges = g.outgoing[current]
		} else {
			edges = g.incoming[current]
		}

		for _, edge := range edges {
			var target string
			if direction == "forward" {
				target = edge.To
			} else {
				target = edge.From
			}

			if !visited[target] {
				visited[target] = true
				queue = append(queue, target)
			}
		}
	}

	// Remove the starting unit from the result
	delete(visited, unit)

	result := make([]string, 0, len(visited))
	for name := range visited {
		result = append(result, name)
	}
	sort.Strings(result)

	return result
}

// TransitiveDependencies returns all units that a unit transitively depends on.
func (g *Graph) TransitiveDependencies(unit string) []string {
	return g.ReachableFrom(unit, "forward")
}

// TransitiveDependents returns all units that transitively depend on a unit.
func (g *Graph) TransitiveDependents(unit string) []string {
	return g.ReachableFrom(unit, "backward")
}

// PathBetween finds a path between two units if one exists.
// Returns nil if no path exists.
func (g *Graph) PathBetween(from, to string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// BFS to find shortest path
	visited := make(map[string]bool)
	parent := make(map[string]string)
	queue := []string{from}
	visited[from] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == to {
			// Reconstruct path
			path := []string{to}
			for path[len(path)-1] != from {
				path = append(path, parent[path[len(path)-1]])
			}
			// Reverse path
			for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
				path[i], path[j] = path[j], path[i]
			}
			return path
		}

		for _, edge := range g.outgoing[current] {
			if !visited[edge.To] {
				visited[edge.To] = true
				parent[edge.To] = current
				queue = append(queue, edge.To)
			}
		}
	}

	return nil // No path found
}
