package graph

import (
	"path/filepath"
	"testing"

	"github.com/supabase/sdaudit/internal/analyzer"
	"github.com/supabase/sdaudit/pkg/types"
)

func loadTestUnits(t *testing.T, path string) map[string]*types.UnitFile {
	t.Helper()
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	units, err := analyzer.LoadUnitsFromDirectory(absPath)
	if err != nil {
		t.Fatalf("failed to load units from %s: %v", path, err)
	}
	return units
}

func TestBuildGraph(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")

	g := Build(units)

	if len(g.Units()) != 3 {
		t.Errorf("expected 3 units, got %d", len(g.Units()))
	}

	edges := g.Edges()
	if len(edges) == 0 {
		t.Error("expected edges, got none")
	}

	// Check that edges were created
	requiresCount := 0
	for _, e := range edges {
		if e.Type == EdgeRequires {
			requiresCount++
		}
	}
	if requiresCount != 3 {
		t.Errorf("expected 3 Requires edges, got %d", requiresCount)
	}
}

func TestGraphEdgesFrom(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	g := Build(units)

	edges := g.EdgesFrom("a.service")
	if len(edges) == 0 {
		t.Error("expected edges from a.service")
	}

	found := false
	for _, e := range edges {
		if e.To == "b.service" && e.Type == EdgeRequires {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected edge from a.service to b.service with Requires type")
	}
}

func TestGraphEdgesTo(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	g := Build(units)

	edges := g.EdgesTo("a.service")
	if len(edges) == 0 {
		t.Error("expected edges to a.service")
	}

	found := false
	for _, e := range edges {
		if e.From == "c.service" && e.Type == EdgeRequires {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected edge from c.service to a.service")
	}
}

func TestEdgeTypeStrings(t *testing.T) {
	tests := []struct {
		edgeType EdgeType
		expected string
	}{
		{EdgeRequires, "Requires"},
		{EdgeWants, "Wants"},
		{EdgeBindsTo, "BindsTo"},
		{EdgeAfter, "After"},
		{EdgeBefore, "Before"},
		{EdgeConflicts, "Conflicts"},
		{EdgePartOf, "PartOf"},
	}

	for _, tt := range tests {
		if got := tt.edgeType.String(); got != tt.expected {
			t.Errorf("EdgeType(%d).String() = %s, want %s", tt.edgeType, got, tt.expected)
		}
	}
}

func TestEdgeTypeProperties(t *testing.T) {
	// Test IsRequirementEdge
	requirementEdges := []EdgeType{EdgeRequires, EdgeWants, EdgeBindsTo, EdgeRequisite}
	for _, et := range requirementEdges {
		if !et.IsRequirementEdge() {
			t.Errorf("%s should be a requirement edge", et.String())
		}
	}

	if EdgeAfter.IsRequirementEdge() {
		t.Error("After should not be a requirement edge")
	}

	// Test IsOrderingEdge
	if !EdgeAfter.IsOrderingEdge() {
		t.Error("After should be an ordering edge")
	}
	if !EdgeBefore.IsOrderingEdge() {
		t.Error("Before should be an ordering edge")
	}
	if EdgeRequires.IsOrderingEdge() {
		t.Error("Requires should not be an ordering edge")
	}

	// Test PropagatesStartFailure
	if !EdgeRequires.PropagatesStartFailure() {
		t.Error("Requires should propagate start failure")
	}
	if EdgeWants.PropagatesStartFailure() {
		t.Error("Wants should not propagate start failure")
	}

	// Test PropagatesStop
	if !EdgeBindsTo.PropagatesStop() {
		t.Error("BindsTo should propagate stop")
	}
	if EdgeRequires.PropagatesStop() {
		t.Error("Requires should not propagate stop")
	}
}
