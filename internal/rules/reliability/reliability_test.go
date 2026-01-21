package reliability

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

func TestREL001_RestartPolicy(t *testing.T) {
	rule := &REL001{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "missing Restart",
			service:    map[string]string{"ExecStart": "/usr/bin/app"},
			wantIssues: 1,
		},
		{
			name:       "Restart=no",
			service:    map[string]string{"Restart": "no"},
			wantIssues: 1,
		},
		{
			name:       "Restart=always",
			service:    map[string]string{"Restart": "always"},
			wantIssues: 0,
		},
		{
			name:       "Restart=on-failure",
			service:    map[string]string{"Restart": "on-failure"},
			wantIssues: 0,
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

func TestREL002_RestartSec(t *testing.T) {
	rule := &REL002{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "no restart configured",
			service:    map[string]string{},
			wantIssues: 0, // no restart, so no issue
		},
		{
			name:       "restart without RestartSec",
			service:    map[string]string{"Restart": "always"},
			wantIssues: 0, // default is fine
		},
		{
			name:       "RestartSec too short",
			service:    map[string]string{"Restart": "always", "RestartSec": "0"},
			wantIssues: 1,
		},
		{
			name:       "RestartSec=100ms",
			service:    map[string]string{"Restart": "always", "RestartSec": "100ms"},
			wantIssues: 1,
		},
		{
			name:       "RestartSec=5",
			service:    map[string]string{"Restart": "always", "RestartSec": "5"},
			wantIssues: 0,
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

func TestREL003_MissingWantedBy(t *testing.T) {
	rule := &REL003{}

	tests := []struct {
		name       string
		install    map[string]string
		wantIssues int
	}{
		{
			name:       "missing WantedBy and RequiredBy",
			install:    map[string]string{},
			wantIssues: 1,
		},
		{
			name:       "has WantedBy",
			install:    map[string]string{"WantedBy": "multi-user.target"},
			wantIssues: 0,
		},
		{
			name:       "has RequiredBy",
			install:    map[string]string{"RequiredBy": "multi-user.target"},
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(nil, nil, tt.install)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestREL008_KillModeNone(t *testing.T) {
	rule := &REL008{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "no KillMode set",
			service:    map[string]string{},
			wantIssues: 0,
		},
		{
			name:       "KillMode=control-group",
			service:    map[string]string{"KillMode": "control-group"},
			wantIssues: 0,
		},
		{
			name:       "KillMode=none",
			service:    map[string]string{"KillMode": "none"},
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

func TestREL010_BindsToWithoutAfter(t *testing.T) {
	rule := &REL010{}

	tests := []struct {
		name       string
		unit       map[string]string
		wantIssues int
	}{
		{
			name:       "no BindsTo",
			unit:       map[string]string{},
			wantIssues: 0,
		},
		{
			name:       "BindsTo with matching After",
			unit:       map[string]string{"BindsTo": "other.service", "After": "other.service"},
			wantIssues: 0,
		},
		{
			name:       "BindsTo without After",
			unit:       map[string]string{"BindsTo": "other.service"},
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(nil, tt.unit, nil)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestRuleMetadata(t *testing.T) {
	testRules := []rules.Rule{
		&REL001{},
		&REL002{},
	}

	for _, rule := range testRules {
		t.Run(rule.ID(), func(t *testing.T) {
			if rule.ID() == "" {
				t.Error("ID should not be empty")
			}
			if rule.Name() == "" {
				t.Error("Name should not be empty")
			}
			if rule.Category() != types.CategoryReliability {
				t.Errorf("Category = %v, want Reliability", rule.Category())
			}
		})
	}
}
