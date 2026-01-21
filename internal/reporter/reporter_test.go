package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/supabase/sdaudit/internal/analyzer"
	"github.com/supabase/sdaudit/pkg/types"
)

func makeScanResult() *analyzer.ScanResult {
	return &analyzer.ScanResult{
		Units: []*types.UnitFile{
			{Name: "test.service", Path: "/etc/systemd/system/test.service", Type: "service"},
		},
		Issues: []types.Issue{
			{
				RuleID:      "SEC001",
				RuleName:    "NoNewPrivileges not set",
				Severity:    types.SeverityHigh,
				Category:    types.CategorySecurity,
				Tags:        []string{"hardening"},
				Unit:        "test.service",
				File:        "/etc/systemd/system/test.service",
				Description: "Service does not set NoNewPrivileges=yes",
				Suggestion:  "Add NoNewPrivileges=yes to [Service]",
				References:  []string{"https://example.com/docs"},
			},
			{
				RuleID:      "REL001",
				RuleName:    "Restart policy not configured",
				Severity:    types.SeverityMedium,
				Category:    types.CategoryReliability,
				Tags:        []string{"restart"},
				Unit:        "test.service",
				File:        "/etc/systemd/system/test.service",
				Description: "Service has no restart policy",
				Suggestion:  "Add Restart=on-failure to [Service]",
				References:  []string{"https://example.com/docs"},
			},
		},
		Summary: analyzer.Summary{
			TotalUnits:   1,
			TotalIssues:  2,
			RulesChecked: 40,
			BySeverity: map[types.Severity]int{
				types.SeverityHigh:   1,
				types.SeverityMedium: 1,
			},
			ByCategory: map[types.Category]int{
				types.CategorySecurity:    1,
				types.CategoryReliability: 1,
			},
		},
	}
}

func TestJSONReporter(t *testing.T) {
	result := makeScanResult()
	var buf bytes.Buffer

	reporter := NewJSONReporter(&buf, true)
	err := reporter.Report(result)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	// Verify it's valid JSON
	var output JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Check structure
	if output.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", output.Version, "1.0.0")
	}
	if output.Summary.TotalUnits != 1 {
		t.Errorf("TotalUnits = %d, want %d", output.Summary.TotalUnits, 1)
	}
	if output.Summary.TotalIssues != 2 {
		t.Errorf("TotalIssues = %d, want %d", output.Summary.TotalIssues, 2)
	}
	if len(output.Issues) != 2 {
		t.Errorf("Issues count = %d, want %d", len(output.Issues), 2)
	}

	// Check first issue
	if output.Issues[0].ID != "SEC001" {
		t.Errorf("First issue ID = %q, want %q", output.Issues[0].ID, "SEC001")
	}
	if output.Issues[0].Severity != "high" {
		t.Errorf("First issue Severity = %q, want %q", output.Issues[0].Severity, "high")
	}
}

func TestTextReporter(t *testing.T) {
	result := makeScanResult()
	var buf bytes.Buffer

	reporter := NewTextReporter(&buf, false)
	err := reporter.Report(result)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	output := buf.String()

	// Check that key information is present
	checks := []string{
		"sdaudit scan results",
		"Units scanned: 1",
		"Rules checked: 40",
		"Issues found:  2",
		"SEC001",
		"REL001",
		"test.service",
		"NoNewPrivileges",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Output missing %q", check)
		}
	}
}

func TestTextReporterNoIssues(t *testing.T) {
	result := &analyzer.ScanResult{
		Units: []*types.UnitFile{
			{Name: "good.service"},
		},
		Issues: []types.Issue{},
		Summary: analyzer.Summary{
			TotalUnits:   1,
			TotalIssues:  0,
			RulesChecked: 40,
			BySeverity:   map[types.Severity]int{},
			ByCategory:   map[types.Category]int{},
		},
	}

	var buf bytes.Buffer
	reporter := NewTextReporter(&buf, false)
	err := reporter.Report(result)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No issues found") {
		t.Error("Output should contain 'No issues found' message")
	}
}

func TestSARIFReporter(t *testing.T) {
	result := makeScanResult()
	var buf bytes.Buffer

	reporter := NewSARIFReporter(&buf, true)
	err := reporter.Report(result)
	if err != nil {
		t.Fatalf("Report failed: %v", err)
	}

	// Verify it's valid JSON
	var output SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Invalid SARIF output: %v", err)
	}

	// Check SARIF structure
	if output.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", output.Version, "2.1.0")
	}
	if len(output.Runs) != 1 {
		t.Fatalf("Runs count = %d, want %d", len(output.Runs), 1)
	}

	run := output.Runs[0]
	if run.Tool.Driver.Name != "sdaudit" {
		t.Errorf("Tool name = %q, want %q", run.Tool.Driver.Name, "sdaudit")
	}
	if len(run.Results) != 2 {
		t.Errorf("Results count = %d, want %d", len(run.Results), 2)
	}

	// Rules array should exist (may be empty if no rules registered in test)
	if run.Tool.Driver.Rules == nil {
		t.Error("Rules should not be nil")
	}

	// Check first result
	if run.Results[0].RuleID != "SEC001" {
		t.Errorf("First result RuleID = %q, want %q", run.Results[0].RuleID, "SEC001")
	}
	if run.Results[0].Level != "error" {
		t.Errorf("First result Level = %q, want %q (high severity maps to error)", run.Results[0].Level, "error")
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		sev  types.Severity
		want string
	}{
		{types.SeverityCritical, "error"},
		{types.SeverityHigh, "error"},
		{types.SeverityMedium, "warning"},
		{types.SeverityLow, "note"},
		{types.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		got := severityToLevel(tt.sev)
		if got != tt.want {
			t.Errorf("severityToLevel(%v) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}
