package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUnitFile(t *testing.T) {
	// Create a temporary unit file
	content := `[Unit]
Description=Test Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/testapp
User=testuser
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.service")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	unit, err := ParseUnitFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseUnitFile failed: %v", err)
	}

	// Check basic properties
	if unit.Name != "test.service" {
		t.Errorf("Name = %q, want %q", unit.Name, "test.service")
	}
	if unit.Type != "service" {
		t.Errorf("Type = %q, want %q", unit.Type, "service")
	}
	if unit.Path != tmpFile {
		t.Errorf("Path = %q, want %q", unit.Path, tmpFile)
	}

	// Check sections exist
	if _, ok := unit.Sections["Unit"]; !ok {
		t.Error("Missing Unit section")
	}
	if _, ok := unit.Sections["Service"]; !ok {
		t.Error("Missing Service section")
	}
	if _, ok := unit.Sections["Install"]; !ok {
		t.Error("Missing Install section")
	}

	// Check directives
	tests := []struct {
		section string
		key     string
		want    string
	}{
		{"Unit", "Description", "Test Service"},
		{"Unit", "After", "network.target"},
		{"Service", "Type", "simple"},
		{"Service", "ExecStart", "/usr/bin/testapp"},
		{"Service", "User", "testuser"},
		{"Service", "Restart", "always"},
		{"Service", "RestartSec", "5"},
		{"Install", "WantedBy", "multi-user.target"},
	}

	for _, tt := range tests {
		got := unit.GetDirective(tt.section, tt.key)
		if got != tt.want {
			t.Errorf("GetDirective(%q, %q) = %q, want %q", tt.section, tt.key, got, tt.want)
		}
	}
}

func TestParseUnitFileMultipleDirectives(t *testing.T) {
	content := `[Service]
ExecStartPre=/usr/bin/prep1
ExecStartPre=/usr/bin/prep2
ExecStartPre=/usr/bin/prep3
ExecStart=/usr/bin/main
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "multi.service")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	unit, err := ParseUnitFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseUnitFile failed: %v", err)
	}

	directives := unit.GetDirectives("Service", "ExecStartPre")
	if len(directives) != 3 {
		t.Errorf("Got %d ExecStartPre directives, want 3", len(directives))
	}
}

func TestParseUnitFileComments(t *testing.T) {
	content := `[Unit]
# This is a comment
Description=Test Service
; This is also a comment
After=network.target
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "comments.service")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	unit, err := ParseUnitFile(tmpFile)
	if err != nil {
		t.Fatalf("ParseUnitFile failed: %v", err)
	}

	if unit.GetDirective("Unit", "Description") != "Test Service" {
		t.Error("Failed to parse directive after comment")
	}
	if unit.GetDirective("Unit", "After") != "network.target" {
		t.Error("Failed to parse directive after semicolon comment")
	}
}

func TestParseUnitFileNotFound(t *testing.T) {
	_, err := ParseUnitFile("/nonexistent/path/test.service")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestGetUnitType(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"nginx.service", "service"},
		{"nginx.socket", "socket"},
		{"backup.timer", "timer"},
		{"dev-sda.mount", "mount"},
		{"tmp.mount", "mount"},
		{"home.automount", "automount"},
		{"swap.swap", "swap"},
		{"emergency.target", "target"},
		{"syslog.path", "path"},
		{"session.slice", "slice"},
		{"machine.scope", "scope"},
		{"unknown.xyz", "xyz"},
	}

	for _, tt := range tests {
		got := getUnitType(tt.filename)
		if got != tt.want {
			t.Errorf("getUnitType(%q) = %q, want %q", tt.filename, got, tt.want)
		}
	}
}
