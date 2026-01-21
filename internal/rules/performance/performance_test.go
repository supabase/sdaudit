package performance

import (
	"testing"

	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func makeTestUnit(serviceDirectives, unitDirectives, installDirectives map[string]string) *types.UnitFile {
	unit := &types.UnitFile{
		Name: "test.service",
		Path: "/etc/systemd/system/test.service",
		Type: "service",
		Sections: map[string]*types.Section{
			"Unit": {
				Name:       "Unit",
				Directives: make(map[string][]types.Directive),
			},
			"Service": {
				Name:       "Service",
				Directives: make(map[string][]types.Directive),
			},
			"Install": {
				Name:       "Install",
				Directives: make(map[string][]types.Directive),
			},
		},
	}

	for k, v := range serviceDirectives {
		unit.Sections["Service"].Directives[k] = []types.Directive{{Key: k, Value: v}}
	}
	for k, v := range unitDirectives {
		unit.Sections["Unit"].Directives[k] = []types.Directive{{Key: k, Value: v}}
	}
	for k, v := range installDirectives {
		unit.Sections["Install"].Directives[k] = []types.Directive{{Key: k, Value: v}}
	}

	return unit
}

func makeTestUnitWithMultipleDirectives(section, key string, values []string) *types.UnitFile {
	unit := &types.UnitFile{
		Name: "test.service",
		Path: "/etc/systemd/system/test.service",
		Type: "service",
		Sections: map[string]*types.Section{
			"Unit": {
				Name:       "Unit",
				Directives: make(map[string][]types.Directive),
			},
			"Service": {
				Name:       "Service",
				Directives: make(map[string][]types.Directive),
			},
			"Install": {
				Name:       "Install",
				Directives: make(map[string][]types.Directive),
			},
		},
	}

	for _, v := range values {
		unit.Sections[section].Directives[key] = append(
			unit.Sections[section].Directives[key],
			types.Directive{Key: key, Value: v},
		)
	}

	return unit
}

func TestPERF001_BootCriticalService(t *testing.T) {
	rule := &PERF001{}

	tests := []struct {
		name       string
		service    map[string]string
		install    map[string]string
		allUnits   map[string]*types.UnitFile
		wantIssues int
	}{
		{
			name:       "not in boot path",
			service:    map[string]string{"Type": "simple"},
			install:    map[string]string{"WantedBy": "some-other.target"},
			wantIssues: 0,
		},
		{
			name:       "in boot path without socket",
			service:    map[string]string{"Type": "simple"},
			install:    map[string]string{"WantedBy": "multi-user.target"},
			wantIssues: 1,
		},
		{
			name:    "in boot path with socket",
			service: map[string]string{"Type": "simple"},
			install: map[string]string{"WantedBy": "multi-user.target"},
			allUnits: map[string]*types.UnitFile{
				"test.socket": {Name: "test.socket", Type: "socket"},
			},
			wantIssues: 0,
		},
		{
			name:       "oneshot in boot path",
			service:    map[string]string{"Type": "oneshot"},
			install:    map[string]string{"WantedBy": "multi-user.target"},
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(tt.service, nil, tt.install)
			ctx := rules.NewContextWithUnits(unit, tt.allUnits)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestPERF002_ExcessiveExecStartPre(t *testing.T) {
	rule := &PERF002{}

	tests := []struct {
		name       string
		preCount   int
		wantIssues int
	}{
		{
			name:       "no ExecStartPre",
			preCount:   0,
			wantIssues: 0,
		},
		{
			name:       "few ExecStartPre",
			preCount:   2,
			wantIssues: 0,
		},
		{
			name:       "many ExecStartPre",
			preCount:   5,
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var preCmds []string
			for i := 0; i < tt.preCount; i++ {
				preCmds = append(preCmds, "/usr/bin/prep")
			}
			unit := makeTestUnitWithMultipleDirectives("Service", "ExecStartPre", preCmds)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestPERF005_TimeoutStartSec(t *testing.T) {
	rule := &PERF005{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "no timeout set",
			service:    map[string]string{},
			wantIssues: 0,
		},
		{
			name:       "reasonable timeout",
			service:    map[string]string{"TimeoutStartSec": "60"},
			wantIssues: 0,
		},
		{
			name:       "timeout 5 minutes",
			service:    map[string]string{"TimeoutStartSec": "300"},
			wantIssues: 0,
		},
		{
			name:       "timeout too long",
			service:    map[string]string{"TimeoutStartSec": "600"},
			wantIssues: 1,
		},
		{
			name:       "timeout infinity",
			service:    map[string]string{"TimeoutStartSec": "infinity"},
			wantIssues: 0,
		},
		{
			name:       "timeout with unit suffix",
			service:    map[string]string{"TimeoutStartSec": "10min"},
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(tt.service, nil, nil)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"0", 0},
		{"1", 1},
		{"60", 60},
		{"1s", 1},
		{"1sec", 1},
		{"100ms", 0.1},
		{"1m", 60},
		{"1min", 60},
		{"1h", 3600},
		{"5m", 300},
		{"10min", 600},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseTime(tt.input)
			if got != tt.want {
				t.Errorf("parseTime(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRuleMetadata(t *testing.T) {
	testRules := []rules.Rule{
		&PERF001{},
		&PERF002{},
		&PERF003{},
		&PERF004{},
		&PERF005{},
	}

	for _, rule := range testRules {
		t.Run(rule.ID(), func(t *testing.T) {
			if rule.ID() == "" {
				t.Error("ID should not be empty")
			}
			if rule.Name() == "" {
				t.Error("Name should not be empty")
			}
			if rule.Description() == "" {
				t.Error("Description should not be empty")
			}
			if rule.Suggestion() == "" {
				t.Error("Suggestion should not be empty")
			}
			if rule.Category() != types.CategoryPerformance {
				t.Errorf("Category = %v, want Performance", rule.Category())
			}
			if len(rule.Tags()) == 0 {
				t.Error("Tags should not be empty")
			}
			if len(rule.References()) == 0 {
				t.Error("References should not be empty")
			}
		})
	}
}

func TestNonServiceUnit(t *testing.T) {
	rule := &PERF002{} // ExecStartPre rule only applies to services

	unit := &types.UnitFile{
		Name: "test.timer",
		Type: "timer",
		Sections: map[string]*types.Section{
			"Timer": {
				Name:       "Timer",
				Directives: make(map[string][]types.Directive),
			},
		},
	}

	ctx := rules.NewContext(unit)
	issues := rule.Check(ctx)

	if len(issues) != 0 {
		t.Errorf("Performance rules should not apply to non-service units, got %d issues", len(issues))
	}
}
