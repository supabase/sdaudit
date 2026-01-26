package propagation

import (
	"path/filepath"
	"testing"

	"github.com/supabase/sdaudit/internal/analyzer"
	"github.com/supabase/sdaudit/internal/graph"
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

func TestDetectRestartStorms(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/propagation/restart_storm")
	g := graph.Build(units)

	result := DetectRestartStorms(g, units)

	if result.TotalStorms == 0 {
		t.Error("expected restart storms to be detected")
	}

	// Should detect the mutual BindsTo with Restart=on-failure
	found := false
	for _, storm := range result.Storms {
		unitSet := make(map[string]bool)
		for _, u := range storm.Units {
			unitSet[u] = true
		}
		if unitSet["a.service"] && unitSet["b.service"] {
			found = true
			if storm.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", storm.Severity)
			}
			break
		}
	}

	if !found {
		t.Error("expected to find restart storm involving a.service and b.service")
	}
}

func TestDetectDeadlocks(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/propagation/deadlock")
	g := graph.Build(units)

	result := DetectDeadlocks(g, units)

	if result.TotalDeadlocks == 0 {
		t.Error("expected deadlocks to be detected")
	}

	// Should detect the BindsTo + After with reverse Requires
	found := false
	for _, dl := range result.Deadlocks {
		if (dl.UnitA == "primary.service" && dl.UnitB == "secondary.service") ||
			(dl.UnitA == "secondary.service" && dl.UnitB == "primary.service") {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find deadlock between primary.service and secondary.service")
	}
}

func TestSimulateFailure(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/propagation/restart_storm")
	g := graph.Build(units)

	impact := SimulateFailure(g, "a.service")

	if impact.FailedUnit != "a.service" {
		t.Errorf("expected FailedUnit=a.service, got %s", impact.FailedUnit)
	}

	// b.service should be affected because it has BindsTo=a.service
	found := false
	for _, affected := range impact.AffectedUnits {
		if affected.Name == "b.service" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected b.service to be affected by a.service failure")
	}
}

func TestGetSemantics(t *testing.T) {
	// Test Requires semantics
	reqSem := GetSemantics(graph.EdgeRequires)
	if !reqSem.StartFailure {
		t.Error("Requires should propagate start failure")
	}
	if reqSem.StopPropagates {
		t.Error("Requires should not propagate stop")
	}

	// Test BindsTo semantics
	bindsSem := GetSemantics(graph.EdgeBindsTo)
	if !bindsSem.StartFailure {
		t.Error("BindsTo should propagate start failure")
	}
	if !bindsSem.StopPropagates {
		t.Error("BindsTo should propagate stop")
	}

	// Test Wants semantics
	wantsSem := GetSemantics(graph.EdgeWants)
	if wantsSem.StartFailure {
		t.Error("Wants should not propagate start failure")
	}
	if wantsSem.StopPropagates {
		t.Error("Wants should not propagate stop")
	}

	// Test PartOf semantics
	partOfSem := GetSemantics(graph.EdgePartOf)
	if partOfSem.StartFailure {
		t.Error("PartOf should not propagate start failure")
	}
	if !partOfSem.StopPropagates {
		t.Error("PartOf should propagate stop")
	}
}

func TestAnalyzeRestartBehavior(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/propagation/restart_storm")
	g := graph.Build(units)

	behavior := AnalyzeRestartBehavior("a.service", g, units)

	if behavior == nil {
		t.Fatal("expected non-nil behavior")
	}

	if behavior.RestartPolicy != "on-failure" {
		t.Errorf("expected RestartPolicy=on-failure, got %s", behavior.RestartPolicy)
	}

	if !behavior.HasBindsTo {
		t.Error("expected HasBindsTo to be true")
	}

	if len(behavior.BoundToUnits) == 0 {
		t.Error("expected BoundToUnits to contain b.service")
	}

	if behavior.StormRisk == "none" {
		t.Error("expected storm risk to be detected")
	}
}

func TestDetectSilentFailures(t *testing.T) {
	// Create a simple graph with Wants= to a "critical" service
	units := map[string]*types.UnitFile{
		"app.service": {
			Name: "app.service",
			Type: "service",
			Path: "/etc/systemd/system/app.service",
			Sections: map[string]*types.Section{
				"Unit": {
					Name: "Unit",
					Directives: map[string][]types.Directive{
						"Wants": {{Value: "dbus.service", Line: 3}},
					},
				},
			},
		},
		"dbus.service": {
			Name: "dbus.service",
			Type: "service",
			Path: "/lib/systemd/system/dbus.service",
			Sections: map[string]*types.Section{
				"Service": {
					Name: "Service",
					Directives: map[string][]types.Directive{
						"ExecStart": {{Value: "/usr/bin/dbus-daemon"}},
					},
				},
			},
		},
	}

	g := graph.Build(units)
	failures := DetectSilentFailures(g, nil) // nil uses default critical units

	// dbus.service is in the default critical list
	found := false
	for _, f := range failures {
		if f.Unit == "dbus.service" && f.DependedBy == "app.service" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to detect silent failure risk for dbus.service")
	}
}
