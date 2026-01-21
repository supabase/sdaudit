package rules

import (
	"testing"

	"github.com/supabase/sdaudit/pkg/types"
)

func TestContext(t *testing.T) {
	unit := &types.UnitFile{
		Name: "test.service",
		Path: "/etc/systemd/system/test.service",
		Type: "service",
	}

	ctx := NewContext(unit)

	if ctx.Unit != unit {
		t.Error("Context should contain the unit")
	}
	if ctx.Config == nil {
		t.Error("Context should have a default config")
	}
}

func TestContextWithUnits(t *testing.T) {
	unit := &types.UnitFile{
		Name: "test.service",
	}
	allUnits := map[string]*types.UnitFile{
		"test.service":  unit,
		"other.service": {Name: "other.service"},
	}

	ctx := NewContextWithUnits(unit, allUnits)

	if len(ctx.AllUnits) != 2 {
		t.Errorf("AllUnits count = %d, want 2", len(ctx.AllUnits))
	}
}

func TestConfigRuleDisabled(t *testing.T) {
	config := &Config{
		DisabledRules: map[string]bool{"SEC001": true, "SEC002": true},
	}

	ctx := &Context{Config: config}

	if !ctx.IsRuleDisabled("SEC001") {
		t.Error("SEC001 should be disabled")
	}
	if !ctx.IsRuleDisabled("SEC002") {
		t.Error("SEC002 should be disabled")
	}
	if ctx.IsRuleDisabled("SEC003") {
		t.Error("SEC003 should not be disabled")
	}
}

func TestConfigSeverityOverride(t *testing.T) {
	config := &Config{
		SeverityOverrides: map[string]types.Severity{
			"SEC001": types.SeverityCritical,
		},
	}

	ctx := &Context{Config: config}

	sev, ok := ctx.GetSeverityOverride("SEC001")
	if !ok {
		t.Error("Should have override for SEC001")
	}
	if sev != types.SeverityCritical {
		t.Errorf("Override = %v, want Critical", sev)
	}

	_, ok = ctx.GetSeverityOverride("SEC002")
	if ok {
		t.Error("Should not have override for SEC002")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig should not return nil")
	}

	ctx := &Context{Config: config}

	// Default config should not disable any rules
	if ctx.IsRuleDisabled("SEC001") {
		t.Error("Default config should not disable rules")
	}

	// Default config should not have overrides
	if _, ok := ctx.GetSeverityOverride("SEC001"); ok {
		t.Error("Default config should not have severity overrides")
	}
}

func TestAllRulesAreSorted(t *testing.T) {
	allRules := All()

	if len(allRules) == 0 {
		t.Skip("No rules registered")
	}

	// Check that rules are sorted by ID
	for i := 1; i < len(allRules); i++ {
		if allRules[i-1].ID() > allRules[i].ID() {
			t.Errorf("Rules not sorted: %s > %s", allRules[i-1].ID(), allRules[i].ID())
		}
	}
}
