package security

import (
	"testing"

	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/pkg/types"
)

func makeTestUnit(directives map[string]string) *types.UnitFile {
	unit := &types.UnitFile{
		Name: "test.service",
		Path: "/etc/systemd/system/test.service",
		Type: "service",
		Sections: map[string]*types.Section{
			"Service": {
				Name:       "Service",
				Directives: make(map[string][]types.Directive),
			},
		},
	}

	for k, v := range directives {
		unit.Sections["Service"].Directives[k] = []types.Directive{{Key: k, Value: v}}
	}

	return unit
}

func TestSEC001_NoNewPrivileges(t *testing.T) {
	rule := &SEC001{}

	tests := []struct {
		name       string
		directives map[string]string
		wantIssues int
	}{
		{
			name:       "missing NoNewPrivileges",
			directives: map[string]string{"ExecStart": "/usr/bin/app"},
			wantIssues: 1,
		},
		{
			name:       "NoNewPrivileges=no",
			directives: map[string]string{"NoNewPrivileges": "no"},
			wantIssues: 1,
		},
		{
			name:       "NoNewPrivileges=yes",
			directives: map[string]string{"NoNewPrivileges": "yes"},
			wantIssues: 0,
		},
		{
			name:       "NoNewPrivileges=true",
			directives: map[string]string{"NoNewPrivileges": "true"},
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(tt.directives)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestSEC002_PrivateTmp(t *testing.T) {
	rule := &SEC002{}

	tests := []struct {
		name       string
		directives map[string]string
		wantIssues int
	}{
		{
			name:       "missing PrivateTmp",
			directives: map[string]string{},
			wantIssues: 1,
		},
		{
			name:       "PrivateTmp=yes",
			directives: map[string]string{"PrivateTmp": "yes"},
			wantIssues: 0,
		},
		{
			name:       "PrivateTmp=no",
			directives: map[string]string{"PrivateTmp": "no"},
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(tt.directives)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestSEC003_ProtectSystem(t *testing.T) {
	rule := &SEC003{}

	tests := []struct {
		name       string
		directives map[string]string
		wantIssues int
	}{
		{
			name:       "missing ProtectSystem",
			directives: map[string]string{},
			wantIssues: 1,
		},
		{
			name:       "ProtectSystem=strict",
			directives: map[string]string{"ProtectSystem": "strict"},
			wantIssues: 0,
		},
		{
			name:       "ProtectSystem=full",
			directives: map[string]string{"ProtectSystem": "full"},
			wantIssues: 0,
		},
		{
			name:       "ProtectSystem=yes",
			directives: map[string]string{"ProtectSystem": "yes"},
			wantIssues: 1, // yes is weaker than strict/full
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(tt.directives)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestSEC005_RootService(t *testing.T) {
	rule := &SEC005{}

	tests := []struct {
		name       string
		directives map[string]string
		wantIssues int
	}{
		{
			name:       "root with no hardening",
			directives: map[string]string{},
			wantIssues: 1,
		},
		{
			name:       "non-root user",
			directives: map[string]string{"User": "nobody"},
			wantIssues: 0,
		},
		{
			name:       "DynamicUser",
			directives: map[string]string{"DynamicUser": "yes"},
			wantIssues: 0,
		},
		{
			name: "root with hardening",
			directives: map[string]string{
				"NoNewPrivileges":       "yes",
				"ProtectSystem":         "strict",
				"ProtectHome":           "yes",
				"PrivateTmp":            "yes",
				"PrivateDevices":        "yes",
				"ProtectKernelTunables": "yes",
				"ProtectKernelModules":  "yes",
			},
			wantIssues: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unit := makeTestUnit(tt.directives)
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
		&SEC001{},
		&SEC002{},
		&SEC003{},
		&SEC004{},
		&SEC005{},
		&SEC006{},
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
			if rule.Category() != types.CategorySecurity {
				t.Errorf("Category = %v, want Security", rule.Category())
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
	rule := &SEC001{}

	// Create a socket unit (not a service)
	unit := &types.UnitFile{
		Name: "test.socket",
		Type: "socket",
		Sections: map[string]*types.Section{
			"Socket": {
				Name:       "Socket",
				Directives: make(map[string][]types.Directive),
			},
		},
	}

	ctx := rules.NewContext(unit)
	issues := rule.Check(ctx)

	if len(issues) != 0 {
		t.Errorf("Security rules should not apply to non-service units, got %d issues", len(issues))
	}
}
