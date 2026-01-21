package bestpractice

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

func TestBP002_DeprecatedDirectives(t *testing.T) {
	rule := &BP002{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "no deprecated directives",
			service:    map[string]string{"ExecStart": "/usr/bin/app"},
			wantIssues: 0,
		},
		{
			name:       "PermissionsStartOnly deprecated",
			service:    map[string]string{"PermissionsStartOnly": "true"},
			wantIssues: 1,
		},
		{
			name:       "StartLimitInterval deprecated",
			service:    map[string]string{"StartLimitInterval": "10s"},
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

func TestBP003_ExecStartAbsolutePath(t *testing.T) {
	rule := &BP003{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "absolute path",
			service:    map[string]string{"ExecStart": "/usr/bin/app"},
			wantIssues: 0,
		},
		{
			name:       "absolute path with prefix",
			service:    map[string]string{"ExecStart": "-/usr/bin/app"},
			wantIssues: 0,
		},
		{
			name:       "relative path",
			service:    map[string]string{"ExecStart": "app"},
			wantIssues: 1,
		},
		{
			name:       "no ExecStart",
			service:    map[string]string{},
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

func TestBP004_MissingDocumentation(t *testing.T) {
	rule := &BP004{}

	tests := []struct {
		name       string
		unit       map[string]string
		wantIssues int
	}{
		{
			name:       "missing Documentation",
			unit:       map[string]string{"Description": "Test"},
			wantIssues: 1,
		},
		{
			name:       "has Documentation",
			unit:       map[string]string{"Documentation": "man:test(8)"},
			wantIssues: 0,
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

func TestBP005_EnvironmentInUnitFile(t *testing.T) {
	rule := &BP005{}

	tests := []struct {
		name       string
		envCount   int
		wantIssues int
	}{
		{
			name:       "no environment variables",
			envCount:   0,
			wantIssues: 0,
		},
		{
			name:       "few environment variables",
			envCount:   2,
			wantIssues: 0,
		},
		{
			name:       "many environment variables",
			envCount:   5,
			wantIssues: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var envs []string
			for i := 0; i < tt.envCount; i++ {
				envs = append(envs, "VAR=value")
			}
			unit := makeTestUnitWithMultipleDirectives("Service", "Environment", envs)
			ctx := rules.NewContext(unit)
			issues := rule.Check(ctx)

			if len(issues) != tt.wantIssues {
				t.Errorf("got %d issues, want %d", len(issues), tt.wantIssues)
			}
		})
	}
}

func TestBP008_MissingDescription(t *testing.T) {
	rule := &BP008{}

	tests := []struct {
		name       string
		unit       map[string]string
		wantIssues int
	}{
		{
			name:       "missing Description",
			unit:       map[string]string{},
			wantIssues: 1,
		},
		{
			name:       "has Description",
			unit:       map[string]string{"Description": "My Service"},
			wantIssues: 0,
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

func TestBP010_OneshotWithoutRemainAfterExit(t *testing.T) {
	rule := &BP010{}

	tests := []struct {
		name       string
		service    map[string]string
		wantIssues int
	}{
		{
			name:       "not oneshot",
			service:    map[string]string{"Type": "simple"},
			wantIssues: 0,
		},
		{
			name:       "oneshot without RemainAfterExit",
			service:    map[string]string{"Type": "oneshot"},
			wantIssues: 1,
		},
		{
			name:       "oneshot with RemainAfterExit",
			service:    map[string]string{"Type": "oneshot", "RemainAfterExit": "yes"},
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

func TestRuleMetadata(t *testing.T) {
	testRules := []rules.Rule{
		&BP001{},
		&BP002{},
		&BP003{},
		&BP004{},
		&BP005{},
		&BP006{},
		&BP007{},
		&BP008{},
		&BP009{},
		&BP010{},
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
			if rule.Category() != types.CategoryBestPractice {
				t.Errorf("Category = %v, want BestPractice", rule.Category())
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
	rule := &BP003{} // ExecStart rule only applies to services

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
		t.Errorf("Best practice rules should not apply to non-service units, got %d issues", len(issues))
	}
}
