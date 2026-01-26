package timing

import (
	"sort"
	"time"

	"github.com/supabase/sdaudit/internal/graph"
)

// PathNode represents a unit in a critical path.
type PathNode struct {
	Unit       string
	Timeout    time.Duration
	Cumulative time.Duration // Running total at this point
}

// CriticalPath represents the longest startup chain to reach a unit.
type CriticalPath struct {
	Unit       string
	TotalTime  time.Duration // Sum of timeouts along path
	Path       []PathNode    // Units in order
	Bottleneck string        // Unit contributing most time
}

// CriticalPathResult contains all computed critical paths.
type CriticalPathResult struct {
	Paths           map[string]CriticalPath
	LongestPath     CriticalPath
	BottleneckUnits []string // Units appearing frequently as bottlenecks
}

// ComputeCriticalPaths walks the After= graph backward from each unit.
// Returns the worst-case startup time chain for each unit.
func ComputeCriticalPaths(g *graph.Graph, timeouts map[string]TimeoutConfig) CriticalPathResult {
	result := CriticalPathResult{
		Paths: make(map[string]CriticalPath),
	}

	// Build After= adjacency for quick lookup (reversed for backward walk)
	// If A After= B, then B must start before A
	// So we track: what must start before this unit?
	afterDeps := make(map[string][]string) // unit -> units it must wait for

	for _, edge := range g.Edges() {
		if edge.Type == graph.EdgeAfter {
			afterDeps[edge.From] = append(afterDeps[edge.From], edge.To)
		}
	}

	// Compute critical path for each unit using dynamic programming with memoization
	memo := make(map[string]CriticalPath)

	var computePath func(unit string, visited map[string]bool) CriticalPath
	computePath = func(unit string, visited map[string]bool) CriticalPath {
		// Check memo
		if path, ok := memo[unit]; ok {
			return path
		}

		// Detect cycles
		if visited[unit] {
			return CriticalPath{Unit: unit}
		}
		visited[unit] = true
		defer delete(visited, unit)

		// Get this unit's timeout
		timeout := DefaultTimeoutStartSec
		if tc, ok := timeouts[unit]; ok {
			timeout = tc.TimeoutStartSec
		}

		// Find the longest path among all dependencies
		var longestDep CriticalPath
		for _, dep := range afterDeps[unit] {
			depPath := computePath(dep, visited)
			if depPath.TotalTime > longestDep.TotalTime {
				longestDep = depPath
			}
		}

		// Build this unit's path
		path := CriticalPath{
			Unit:      unit,
			TotalTime: longestDep.TotalTime + timeout,
			Path:      make([]PathNode, len(longestDep.Path)+1),
		}

		// Copy dependency path and add this unit
		copy(path.Path, longestDep.Path)
		cumulative := longestDep.TotalTime + timeout
		path.Path[len(path.Path)-1] = PathNode{
			Unit:       unit,
			Timeout:    timeout,
			Cumulative: cumulative,
		}

		// Find bottleneck (unit with largest timeout in path)
		var maxTimeout time.Duration
		for _, node := range path.Path {
			if node.Timeout > maxTimeout {
				maxTimeout = node.Timeout
				path.Bottleneck = node.Unit
			}
		}

		memo[unit] = path
		return path
	}

	// Compute for all units
	for _, unit := range g.Units() {
		visited := make(map[string]bool)
		path := computePath(unit.Name, visited)
		result.Paths[unit.Name] = path

		if path.TotalTime > result.LongestPath.TotalTime {
			result.LongestPath = path
		}
	}

	// Find bottleneck units (appear frequently as bottleneck)
	bottleneckCount := make(map[string]int)
	for _, path := range result.Paths {
		if path.Bottleneck != "" {
			bottleneckCount[path.Bottleneck]++
		}
	}

	// Sort by frequency
	type bottleneck struct {
		unit  string
		count int
	}
	var bottlenecks []bottleneck
	for unit, count := range bottleneckCount {
		bottlenecks = append(bottlenecks, bottleneck{unit, count})
	}
	sort.Slice(bottlenecks, func(i, j int) bool {
		return bottlenecks[i].count > bottlenecks[j].count
	})

	for _, b := range bottlenecks {
		result.BottleneckUnits = append(result.BottleneckUnits, b.unit)
	}

	return result
}

// PathsExceedingThreshold returns all critical paths exceeding a threshold.
func (r CriticalPathResult) PathsExceedingThreshold(threshold time.Duration) []CriticalPath {
	var paths []CriticalPath
	for _, path := range r.Paths {
		if path.TotalTime > threshold {
			paths = append(paths, path)
		}
	}

	// Sort by total time descending
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].TotalTime > paths[j].TotalTime
	})

	return paths
}

// PathForUnit returns the critical path for a specific unit.
func (r CriticalPathResult) PathForUnit(unit string) (CriticalPath, bool) {
	path, ok := r.Paths[unit]
	return path, ok
}

// BootCriticalUnits returns units on the critical path to common boot targets.
func ComputeBootCriticalUnits(g *graph.Graph, timeouts map[string]TimeoutConfig) []string {
	paths := ComputeCriticalPaths(g, timeouts)

	// Find paths to common boot targets
	bootTargets := []string{
		"default.target",
		"multi-user.target",
		"graphical.target",
		"basic.target",
	}

	criticalUnits := make(map[string]bool)
	for _, target := range bootTargets {
		if path, ok := paths.Paths[target]; ok {
			for _, node := range path.Path {
				criticalUnits[node.Unit] = true
			}
		}
	}

	result := make([]string, 0, len(criticalUnits))
	for unit := range criticalUnits {
		result = append(result, unit)
	}
	sort.Strings(result)

	return result
}

// PathDescription returns a human-readable description of a critical path.
func (p CriticalPath) PathDescription() string {
	if len(p.Path) == 0 {
		return p.Unit + " (no dependencies)"
	}

	desc := ""
	for i, node := range p.Path {
		if i > 0 {
			desc += " -> "
		}
		desc += node.Unit
	}
	return desc
}
