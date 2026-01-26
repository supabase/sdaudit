package graph

import (
	"sort"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// Builder constructs a Graph from parsed unit files.
type Builder struct {
	graph *Graph
}

// NewBuilder creates a new graph builder.
func NewBuilder() *Builder {
	return &Builder{
		graph: New(),
	}
}

// BuildFromUnits constructs the dependency graph from a map of unit files.
// Units are processed in lexicographic order for determinism.
func (b *Builder) BuildFromUnits(units map[string]*types.UnitFile) *Graph {
	// Sort unit names for deterministic processing
	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}
	sort.Strings(names)

	// First pass: add all units as nodes
	for _, name := range names {
		b.graph.AddUnit(units[name])
	}

	// Second pass: extract and add edges
	for _, name := range names {
		unit := units[name]
		b.extractEdges(unit)
	}

	return b.graph
}

// extractEdges extracts all dependency edges from a unit file.
func (b *Builder) extractEdges(unit *types.UnitFile) {
	// Unit section dependencies
	if unitSection, ok := unit.Sections["Unit"]; ok {
		for directive, edgeType := range DirectiveToEdgeType {
			if directives, ok := unitSection.Directives[directive]; ok {
				for _, d := range directives {
					b.addEdgesFromDirective(unit.Name, d, edgeType, unit.Path)
				}
			}
		}
	}

	// Install section - reverse dependencies
	if installSection, ok := unit.Sections["Install"]; ok {
		// WantedBy creates a reverse Wants edge
		if directives, ok := installSection.Directives["WantedBy"]; ok {
			for _, d := range directives {
				targets := splitDirectiveValue(d.Value)
				for _, target := range targets {
					b.graph.AddEdge(Edge{
						From:     target,
						To:       unit.Name,
						Type:     EdgeWants,
						File:     unit.Path,
						Line:     d.Line,
						Implicit: false,
					})
				}
			}
		}

		// RequiredBy creates a reverse Requires edge
		if directives, ok := installSection.Directives["RequiredBy"]; ok {
			for _, d := range directives {
				targets := splitDirectiveValue(d.Value)
				for _, target := range targets {
					b.graph.AddEdge(Edge{
						From:     target,
						To:       unit.Name,
						Type:     EdgeRequires,
						File:     unit.Path,
						Line:     d.Line,
						Implicit: false,
					})
				}
			}
		}
	}

	// Socket activation: socket units trigger their matching service
	if unit.Type == "socket" {
		serviceName := b.getSocketService(unit)
		if serviceName != "" {
			// Find the line for ListenStream or ListenDatagram for context
			line := 0
			if socketSection, ok := unit.Sections["Socket"]; ok {
				if directives, ok := socketSection.Directives["ListenStream"]; ok && len(directives) > 0 {
					line = directives[0].Line
				} else if directives, ok := socketSection.Directives["ListenDatagram"]; ok && len(directives) > 0 {
					line = directives[0].Line
				}
			}
			b.graph.AddEdge(Edge{
				From:     unit.Name,
				To:       serviceName,
				Type:     EdgeTriggeredBy,
				File:     unit.Path,
				Line:     line,
				Implicit: true,
			})
		}
	}

	// Timer activation: timer units trigger their matching service
	if unit.Type == "timer" {
		serviceName := b.getTimerService(unit)
		if serviceName != "" {
			line := 0
			if timerSection, ok := unit.Sections["Timer"]; ok {
				if directives, ok := timerSection.Directives["OnCalendar"]; ok && len(directives) > 0 {
					line = directives[0].Line
				} else if directives, ok := timerSection.Directives["OnBootSec"]; ok && len(directives) > 0 {
					line = directives[0].Line
				}
			}
			b.graph.AddEdge(Edge{
				From:     unit.Name,
				To:       serviceName,
				Type:     EdgeTriggeredBy,
				File:     unit.Path,
				Line:     line,
				Implicit: true,
			})
		}
	}

	// Path activation: path units trigger their matching service
	if unit.Type == "path" {
		serviceName := b.getPathService(unit)
		if serviceName != "" {
			line := 0
			if pathSection, ok := unit.Sections["Path"]; ok {
				for _, directive := range []string{"PathExists", "PathExistsGlob", "PathChanged", "PathModified", "DirectoryNotEmpty"} {
					if directives, ok := pathSection.Directives[directive]; ok && len(directives) > 0 {
						line = directives[0].Line
						break
					}
				}
			}
			b.graph.AddEdge(Edge{
				From:     unit.Name,
				To:       serviceName,
				Type:     EdgeTriggeredBy,
				File:     unit.Path,
				Line:     line,
				Implicit: true,
			})
		}
	}
}

// addEdgesFromDirective parses a directive value and adds edges for each target.
func (b *Builder) addEdgesFromDirective(from string, directive types.Directive, edgeType EdgeType, file string) {
	targets := splitDirectiveValue(directive.Value)
	for _, target := range targets {
		b.graph.AddEdge(Edge{
			From: from,
			To:   target,
			Type: edgeType,
			File: file,
			Line: directive.Line,
		})
	}
}

// getSocketService returns the service name a socket activates.
func (b *Builder) getSocketService(unit *types.UnitFile) string {
	// Check explicit Service= directive
	if socketSection, ok := unit.Sections["Socket"]; ok {
		if directives, ok := socketSection.Directives["Service"]; ok && len(directives) > 0 {
			return directives[0].Value
		}
	}

	// Default: same name with .service extension
	return strings.TrimSuffix(unit.Name, ".socket") + ".service"
}

// getTimerService returns the service name a timer activates.
func (b *Builder) getTimerService(unit *types.UnitFile) string {
	// Check explicit Unit= directive
	if timerSection, ok := unit.Sections["Timer"]; ok {
		if directives, ok := timerSection.Directives["Unit"]; ok && len(directives) > 0 {
			return directives[0].Value
		}
	}

	// Default: same name with .service extension
	return strings.TrimSuffix(unit.Name, ".timer") + ".service"
}

// getPathService returns the service name a path unit activates.
func (b *Builder) getPathService(unit *types.UnitFile) string {
	// Check explicit Unit= directive
	if pathSection, ok := unit.Sections["Path"]; ok {
		if directives, ok := pathSection.Directives["Unit"]; ok && len(directives) > 0 {
			return directives[0].Value
		}
	}

	// Default: same name with .service extension
	return strings.TrimSuffix(unit.Name, ".path") + ".service"
}

// splitDirectiveValue splits a space-separated directive value into individual targets.
func splitDirectiveValue(value string) []string {
	var targets []string
	for _, part := range strings.Fields(value) {
		part = strings.TrimSpace(part)
		if part != "" {
			targets = append(targets, part)
		}
	}
	return targets
}

// Build is a convenience function to build a graph from units.
func Build(units map[string]*types.UnitFile) *Graph {
	return NewBuilder().BuildFromUnits(units)
}
