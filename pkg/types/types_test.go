package types

import "testing"

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"info", SeverityInfo},
		{"low", SeverityLow},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"critical", SeverityCritical},
		{"unknown", SeverityInfo}, // default
		{"", SeverityInfo},        // default
	}

	for _, tt := range tests {
		if got := ParseSeverity(tt.input); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestCategoryString(t *testing.T) {
	tests := []struct {
		cat  Category
		want string
	}{
		{CategorySecurity, "security"},
		{CategoryPerformance, "performance"},
		{CategoryReliability, "reliability"},
		{CategoryBestPractice, "bestpractice"},
	}

	for _, tt := range tests {
		if got := tt.cat.String(); got != tt.want {
			t.Errorf("Category(%d).String() = %q, want %q", tt.cat, got, tt.want)
		}
	}
}

func TestParseCategory(t *testing.T) {
	tests := []struct {
		input string
		want  Category
	}{
		{"security", CategorySecurity},
		{"performance", CategoryPerformance},
		{"reliability", CategoryReliability},
		{"bestpractice", CategoryBestPractice},
		{"unknown", CategorySecurity}, // default
	}

	for _, tt := range tests {
		if got := ParseCategory(tt.input); got != tt.want {
			t.Errorf("ParseCategory(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestUnitFileGetDirective(t *testing.T) {
	unit := &UnitFile{
		Sections: map[string]*Section{
			"Service": {
				Name: "Service",
				Directives: map[string][]Directive{
					"ExecStart": {{Key: "ExecStart", Value: "/usr/bin/myapp", Line: 5}},
					"User":      {{Key: "User", Value: "nobody", Line: 6}},
				},
			},
		},
	}

	tests := []struct {
		section string
		key     string
		want    string
	}{
		{"Service", "ExecStart", "/usr/bin/myapp"},
		{"Service", "User", "nobody"},
		{"Service", "NotFound", ""},
		{"Unit", "Description", ""},
	}

	for _, tt := range tests {
		if got := unit.GetDirective(tt.section, tt.key); got != tt.want {
			t.Errorf("GetDirective(%q, %q) = %q, want %q", tt.section, tt.key, got, tt.want)
		}
	}
}

func TestUnitFileHasDirective(t *testing.T) {
	unit := &UnitFile{
		Sections: map[string]*Section{
			"Service": {
				Name: "Service",
				Directives: map[string][]Directive{
					"ExecStart": {{Key: "ExecStart", Value: "/usr/bin/myapp", Line: 5}},
				},
			},
		},
	}

	if !unit.HasDirective("Service", "ExecStart") {
		t.Error("HasDirective should return true for existing directive")
	}

	if unit.HasDirective("Service", "NotFound") {
		t.Error("HasDirective should return false for missing directive")
	}

	if unit.HasDirective("Unit", "Description") {
		t.Error("HasDirective should return false for missing section")
	}
}

func TestUnitFileIsService(t *testing.T) {
	service := &UnitFile{Type: "service"}
	socket := &UnitFile{Type: "socket"}
	timer := &UnitFile{Type: "timer"}

	if !service.IsService() {
		t.Error("IsService should return true for service type")
	}
	if service.IsSocket() {
		t.Error("IsSocket should return false for service type")
	}

	if !socket.IsSocket() {
		t.Error("IsSocket should return true for socket type")
	}

	if !timer.IsTimer() {
		t.Error("IsTimer should return true for timer type")
	}
}
