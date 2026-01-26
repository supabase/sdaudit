package graph

import (
	"testing"
)

func TestFindCycles_SimpleCycle(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	g := Build(units)

	cycles := g.FindCycles()

	if len(cycles) != 1 {
		t.Fatalf("expected 1 cycle, got %d", len(cycles))
	}

	cycle := cycles[0]
	if len(cycle.Units) != 3 {
		t.Errorf("expected cycle of 3 units, got %d", len(cycle.Units))
	}

	// All three units should be in the cycle
	unitSet := make(map[string]bool)
	for _, u := range cycle.Units {
		unitSet[u] = true
	}

	for _, expected := range []string{"a.service", "b.service", "c.service"} {
		if !unitSet[expected] {
			t.Errorf("expected %s to be in cycle", expected)
		}
	}
}

func TestFindCycles_NoCycle(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/linear_chain")
	g := Build(units)

	cycles := g.FindCycles()

	if len(cycles) != 0 {
		t.Errorf("expected no cycles, got %d", len(cycles))
	}
}

func TestHasCycles(t *testing.T) {
	// With cycles
	cycleUnits := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	cycleGraph := Build(cycleUnits)
	if !cycleGraph.HasCycles() {
		t.Error("expected HasCycles to return true for cyclic graph")
	}

	// Without cycles
	linearUnits := loadTestUnits(t, "../../testdata/graph/linear_chain")
	linearGraph := Build(linearUnits)
	if linearGraph.HasCycles() {
		t.Error("expected HasCycles to return false for acyclic graph")
	}
}

func TestCycleSeverity(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	g := Build(units)

	cycles := g.FindCycles()
	if len(cycles) == 0 {
		t.Fatal("expected at least one cycle")
	}

	// Cycle with Requires should be critical
	severity := cycles[0].CycleSeverity()
	if severity != "critical" {
		t.Errorf("expected critical severity for Requires cycle, got %s", severity)
	}
}

func TestCycleDescription(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	g := Build(units)

	cycles := g.FindCycles()
	if len(cycles) == 0 {
		t.Fatal("expected at least one cycle")
	}

	desc := cycles[0].CycleDescription()
	if desc == "" {
		t.Error("expected non-empty cycle description")
	}

	// Should contain arrow separators
	if len(cycles[0].Units) > 1 {
		// The description should show the cycle path
		if len(desc) < len(cycles[0].Units[0]) {
			t.Error("cycle description seems too short")
		}
	}
}

func TestFindCyclesInvolving(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/graph/cycle_simple")
	g := Build(units)

	// a.service is part of the cycle
	cycles := g.FindCyclesInvolving("a.service")
	if len(cycles) != 1 {
		t.Errorf("expected 1 cycle involving a.service, got %d", len(cycles))
	}

	// nonexistent.service is not part of any cycle
	cycles = g.FindCyclesInvolving("nonexistent.service")
	if len(cycles) != 0 {
		t.Errorf("expected 0 cycles involving nonexistent.service, got %d", len(cycles))
	}
}
