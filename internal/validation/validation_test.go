package validation

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

func TestValidateService_Valid(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/validation/service_valid")
	unit := units["good.service"]
	if unit == nil {
		t.Fatal("good.service not found")
	}

	// Use mock filesystem that reports everything exists
	fs := NewMockFileSystem()
	fs.Files["/bin/true"] = true
	fs.Executables["/bin/true"] = true
	fs.Users["root"] = true

	result := ValidateService(unit, fs)

	if !result.Valid {
		t.Error("expected valid service")
	}
	if result.ExecStartMissing {
		t.Error("expected ExecStart to be present")
	}
}

func TestValidateService_MissingExecStart(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/validation/service_missing_exec")
	unit := units["bad.service"]
	if unit == nil {
		t.Fatal("bad.service not found")
	}

	fs := NewMockFileSystem()
	result := ValidateService(unit, fs)

	if result.Valid {
		t.Error("expected invalid service")
	}
	if !result.ExecStartMissing {
		t.Error("expected ExecStartMissing to be true")
	}
}

func TestValidateService_UserNotFound(t *testing.T) {
	unit := &types.UnitFile{
		Name: "test.service",
		Type: "service",
		Sections: map[string]*types.Section{
			"Service": {
				Name: "Service",
				Directives: map[string][]types.Directive{
					"ExecStart": {{Value: "/bin/true"}},
					"User":      {{Value: "nonexistent"}},
				},
			},
		},
	}

	// Mock filesystem that reports user doesn't exist
	fs := NewMockFileSystem()
	fs.Files["/bin/true"] = true
	fs.Executables["/bin/true"] = true
	// Users map is empty, so nonexistent won't be found

	result := ValidateService(unit, fs)

	if result.Valid {
		t.Error("expected invalid service")
	}
	if result.UserNotFound != "nonexistent" {
		t.Errorf("expected UserNotFound=nonexistent, got %s", result.UserNotFound)
	}
}

func TestValidateSocket_MissingService(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/validation/socket_no_service")
	unit := units["orphan.socket"]
	if unit == nil {
		t.Fatal("orphan.socket not found")
	}

	result := ValidateSocket(unit, units)

	if result.Valid {
		t.Error("expected invalid socket")
	}
	if !result.MissingService {
		t.Error("expected MissingService to be true")
	}
	if result.ServiceName != "orphan.service" {
		t.Errorf("expected ServiceName=orphan.service, got %s", result.ServiceName)
	}
}

func TestValidateSocket_ValidListen(t *testing.T) {
	tests := []struct {
		directive string
		value     string
		wantErr   bool
	}{
		{"ListenStream", "8080", false},
		{"ListenStream", "127.0.0.1:8080", false},
		{"ListenStream", "[::1]:8080", false},
		{"ListenStream", "/run/test.sock", false},
		{"ListenStream", "@abstract-socket", false},
		{"ListenStream", "99999", true}, // Invalid port
		{"ListenDatagram", "514", false},
		{"ListenFIFO", "/run/fifo", false},
		{"ListenFIFO", "relative/path", true}, // Not absolute
	}

	for _, tt := range tests {
		t.Run(tt.directive+"="+tt.value, func(t *testing.T) {
			result := validateListenValue(tt.directive, tt.value, 1)
			hasErr := result != nil
			if hasErr != tt.wantErr {
				t.Errorf("validateListenValue(%s, %s) error = %v, wantErr %v",
					tt.directive, tt.value, result, tt.wantErr)
			}
		})
	}
}

func TestValidateTimer_NoTrigger(t *testing.T) {
	units := loadTestUnits(t, "../../testdata/validation/timer_no_trigger")
	unit := units["empty.timer"]
	if unit == nil {
		t.Fatal("empty.timer not found")
	}

	result := ValidateTimer(unit, units)

	if result.Valid {
		t.Error("expected invalid timer")
	}
	if !result.NoTrigger {
		t.Error("expected NoTrigger to be true")
	}
}

func TestValidateTimer_ValidCalendar(t *testing.T) {
	tests := []struct {
		value   string
		wantErr bool
	}{
		{"daily", false},
		{"hourly", false},
		{"weekly", false},
		{"*-*-* 00:00:00", false},
		{"Mon *-*-* 10:00", false},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			result := validateCalendarExpression(tt.value, 1)
			hasErr := result != nil
			if hasErr != tt.wantErr {
				t.Errorf("validateCalendarExpression(%q) error = %v, wantErr %v",
					tt.value, result, tt.wantErr)
			}
		})
	}
}

func TestValidateMount_NameMismatch(t *testing.T) {
	unit := &types.UnitFile{
		Name: "wrong-name.mount",
		Type: "mount",
		Sections: map[string]*types.Section{
			"Mount": {
				Name: "Mount",
				Directives: map[string][]types.Directive{
					"What":  {{Value: "/dev/sda1"}},
					"Where": {{Value: "/mnt/data"}},
					"Type":  {{Value: "ext4"}},
				},
			},
		},
	}

	fs := NewMockFileSystem()
	fs.Files["/dev/sda1"] = true

	result := ValidateMount(unit, fs)

	if result.Valid {
		t.Error("expected invalid mount")
	}
	if !result.NameMismatch {
		t.Error("expected NameMismatch to be true")
	}
	// Expected name for /mnt/data is mnt-data.mount
	if result.ExpectedName != "mnt-data.mount" {
		t.Errorf("expected ExpectedName=mnt-data.mount, got %s", result.ExpectedName)
	}
}

func TestPathToMountUnitName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/", "-.mount"},
		{"/home", "home.mount"},
		{"/home/user", "home-user.mount"},
		{"/mnt/data", "mnt-data.mount"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := pathToMountUnitName(tt.path)
			if got != tt.expected {
				t.Errorf("pathToMountUnitName(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestMockFileSystem(t *testing.T) {
	fs := NewMockFileSystem()

	// Test defaults (everything returns false)
	if fs.Exists("/test") {
		t.Error("expected Exists to return false by default")
	}
	if fs.UserExists("testuser") {
		t.Error("expected UserExists to return false by default")
	}

	// Set up mock data
	fs.Files["/test"] = true
	fs.Executables["/test"] = true
	fs.Users["testuser"] = true
	fs.Groups["testgroup"] = true

	// Test that mock data works
	if !fs.Exists("/test") {
		t.Error("expected Exists to return true")
	}
	if !fs.IsExecutable("/test") {
		t.Error("expected IsExecutable to return true")
	}
	if !fs.UserExists("testuser") {
		t.Error("expected UserExists to return true")
	}
	if !fs.GroupExists("testgroup") {
		t.Error("expected GroupExists to return true")
	}
}
