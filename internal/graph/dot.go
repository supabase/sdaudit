package graph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// DOTOptions configures DOT output generation.
type DOTOptions struct {
	Title          string     // Graph title
	IncludeEdges   []EdgeType // Only include these edge types (nil = all)
	ExcludeEdges   []EdgeType // Exclude these edge types
	HighlightUnits []string   // Units to highlight
	HighlightCycle bool       // Highlight units in cycles
	ShowMissing    bool       // Show missing units (dangling refs)
	Clustered      bool       // Group by unit type
}

// DefaultDOTOptions returns sensible defaults for DOT output.
func DefaultDOTOptions() DOTOptions {
	return DOTOptions{
		Title:          "Systemd Unit Dependencies",
		ShowMissing:    true,
		Clustered:      false,
		HighlightCycle: true,
	}
}

// ToDOT exports the graph in Graphviz DOT format.
func (g *Graph) ToDOT(opts DOTOptions) string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder

	sb.WriteString("digraph systemd_units {\n")
	fmt.Fprintf(&sb, "  label=%q;\n", opts.Title)
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=filled, fillcolor=white];\n")
	sb.WriteString("\n")

	// Find units in cycles for highlighting
	cycleUnits := make(map[string]bool)
	if opts.HighlightCycle {
		for _, cycle := range g.FindCycles() {
			for _, unit := range cycle.Units {
				cycleUnits[unit] = true
			}
		}
	}

	// Find missing units
	missingUnits := make(map[string]bool)
	for _, edge := range g.allEdges {
		if _, exists := g.units[edge.To]; !exists {
			missingUnits[edge.To] = true
		}
	}

	// Build highlight set
	highlightSet := make(map[string]bool)
	for _, u := range opts.HighlightUnits {
		highlightSet[u] = true
	}

	// Build include/exclude sets
	includeSet := make(map[EdgeType]bool)
	for _, et := range opts.IncludeEdges {
		includeSet[et] = true
	}
	excludeSet := make(map[EdgeType]bool)
	for _, et := range opts.ExcludeEdges {
		excludeSet[et] = true
	}

	// Output nodes
	if opts.Clustered {
		g.writeDOTClustered(&sb, cycleUnits, missingUnits, highlightSet, opts.ShowMissing)
	} else {
		g.writeDOTNodes(&sb, cycleUnits, missingUnits, highlightSet, opts.ShowMissing)
	}

	// Output edges
	sb.WriteString("\n  // Edges\n")
	edgesSorted := make([]Edge, len(g.allEdges))
	copy(edgesSorted, g.allEdges)
	sort.Slice(edgesSorted, func(i, j int) bool {
		if edgesSorted[i].From != edgesSorted[j].From {
			return edgesSorted[i].From < edgesSorted[j].From
		}
		return edgesSorted[i].To < edgesSorted[j].To
	})

	for _, edge := range edgesSorted {
		// Filter by include/exclude
		if len(includeSet) > 0 && !includeSet[edge.Type] {
			continue
		}
		if excludeSet[edge.Type] {
			continue
		}

		// Skip edges to missing units if not showing missing
		if !opts.ShowMissing && missingUnits[edge.To] {
			continue
		}

		style := edgeStyle(edge.Type)
		fmt.Fprintf(&sb, "  %q -> %q [%s];\n", edge.From, edge.To, style)
	}

	sb.WriteString("}\n")
	return sb.String()
}

// writeDOTNodes writes node definitions without clustering.
func (g *Graph) writeDOTNodes(sb *strings.Builder, cycleUnits, missingUnits, highlightSet map[string]bool, showMissing bool) {
	sb.WriteString("  // Units\n")

	// Collect all nodes
	nodes := make([]string, 0, len(g.nodeIDs))
	for name := range g.nodeIDs {
		nodes = append(nodes, name)
	}
	sort.Strings(nodes)

	for _, name := range nodes {
		isMissing := missingUnits[name]
		if isMissing && !showMissing {
			continue
		}

		attrs := nodeAttributes(name, g.units[name], cycleUnits[name], isMissing, highlightSet[name])
		fmt.Fprintf(sb, "  %q [%s];\n", name, attrs)
	}
}

// writeDOTClustered writes node definitions grouped by unit type.
func (g *Graph) writeDOTClustered(sb *strings.Builder, cycleUnits, missingUnits, highlightSet map[string]bool, showMissing bool) {
	// Group units by type
	byType := make(map[string][]string)
	for name, unit := range g.units {
		if unit != nil {
			byType[unit.Type] = append(byType[unit.Type], name)
		}
	}

	// Add missing units to a separate group
	var missing []string
	for name := range missingUnits {
		if showMissing {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		byType["missing"] = missing
	}

	// Sort types
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)

	for _, unitType := range types {
		units := byType[unitType]
		sort.Strings(units)

		fmt.Fprintf(sb, "  subgraph cluster_%s {\n", unitType)
		fmt.Fprintf(sb, "    label=%q;\n", unitType)

		if unitType == "missing" {
			sb.WriteString("    style=dashed;\n")
			sb.WriteString("    color=red;\n")
		}

		for _, name := range units {
			isMissing := missingUnits[name]
			attrs := nodeAttributes(name, g.units[name], cycleUnits[name], isMissing, highlightSet[name])
			fmt.Fprintf(sb, "    %q [%s];\n", name, attrs)
		}

		sb.WriteString("  }\n")
	}
}

// nodeAttributes returns DOT attributes for a node.
func nodeAttributes(name string, unit *types.UnitFile, inCycle, isMissing, isHighlighted bool) string {
	var attrs []string

	// Color based on state
	if isMissing {
		attrs = append(attrs, "fillcolor=\"#ffcccc\"", "style=\"filled,dashed\"")
	} else if inCycle {
		attrs = append(attrs, "fillcolor=\"#ffeeaa\"", "color=red", "penwidth=2")
	} else if isHighlighted {
		attrs = append(attrs, "fillcolor=\"#aaffaa\"", "penwidth=2")
	} else if unit != nil {
		// Color by type
		switch unit.Type {
		case "service":
			attrs = append(attrs, "fillcolor=\"#e0e0ff\"")
		case "socket":
			attrs = append(attrs, "fillcolor=\"#e0ffe0\"")
		case "timer":
			attrs = append(attrs, "fillcolor=\"#ffe0e0\"")
		case "target":
			attrs = append(attrs, "fillcolor=\"#f0f0f0\"", "shape=ellipse")
		case "mount":
			attrs = append(attrs, "fillcolor=\"#fff0e0\"")
		case "path":
			attrs = append(attrs, "fillcolor=\"#e0f0ff\"")
		}
	}

	return strings.Join(attrs, ", ")
}

// edgeStyle returns DOT style attributes for an edge type.
func edgeStyle(et EdgeType) string {
	switch et {
	case EdgeRequires:
		return "color=blue, penwidth=2, label=Requires"
	case EdgeWants:
		return "color=blue, style=dashed, label=Wants"
	case EdgeBindsTo:
		return "color=purple, penwidth=2, label=BindsTo"
	case EdgeRequisite:
		return "color=blue, penwidth=2, style=bold, label=Requisite"
	case EdgeAfter:
		return "color=gray, style=dotted, label=After"
	case EdgeBefore:
		return "color=gray, style=dotted, label=Before"
	case EdgeConflicts:
		return "color=red, style=dashed, label=Conflicts"
	case EdgePartOf:
		return "color=orange, label=PartOf"
	case EdgePropagatesReloadTo:
		return "color=green, style=dashed, label=PropagatesReloadTo"
	case EdgeReloadPropagatedFrom:
		return "color=green, style=dashed, label=ReloadPropagatedFrom"
	case EdgeTriggeredBy:
		return "color=cyan, label=TriggeredBy"
	default:
		return ""
	}
}

// ToDOTFiltered exports a subgraph containing only the specified units and their direct dependencies.
func (g *Graph) ToDOTFiltered(units []string, opts DOTOptions) string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Build set of units to include
	includeUnits := make(map[string]bool)
	for _, u := range units {
		includeUnits[u] = true
		// Include direct dependencies
		for _, edge := range g.outgoing[u] {
			includeUnits[edge.To] = true
		}
		// Include direct dependents
		for _, edge := range g.incoming[u] {
			includeUnits[edge.From] = true
		}
	}

	// Create a filtered graph
	filtered := New()
	for name := range includeUnits {
		if unit, ok := g.units[name]; ok && unit != nil {
			filtered.AddUnit(unit)
		}
	}

	for _, edge := range g.allEdges {
		if includeUnits[edge.From] && includeUnits[edge.To] {
			filtered.AddEdge(edge)
		}
	}

	return filtered.ToDOT(opts)
}
