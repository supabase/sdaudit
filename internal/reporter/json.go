package reporter

import (
	"encoding/json"
	"io"
	"time"

	"github.com/supabase/sdaudit/internal/analyzer"
)

// JSONReporter outputs scan results in JSON format
type JSONReporter struct {
	w      io.Writer
	pretty bool
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(w io.Writer, pretty bool) *JSONReporter {
	return &JSONReporter{w: w, pretty: pretty}
}

// JSONOutput represents the JSON output structure
type JSONOutput struct {
	Version   string      `json:"version"`
	Timestamp string      `json:"timestamp"`
	Summary   JSONSummary `json:"summary"`
	Issues    []JSONIssue `json:"issues"`
}

// JSONSummary represents the summary in JSON output
type JSONSummary struct {
	TotalUnits   int            `json:"total_units"`
	TotalIssues  int            `json:"total_issues"`
	RulesChecked int            `json:"rules_checked"`
	BySeverity   map[string]int `json:"by_severity"`
	ByCategory   map[string]int `json:"by_category"`
}

// JSONIssue represents an issue in JSON output
type JSONIssue struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags"`
	Unit        string   `json:"unit"`
	File        string   `json:"file"`
	Line        *int     `json:"line,omitempty"`
	Description string   `json:"description"`
	Suggestion  string   `json:"suggestion"`
	References  []string `json:"references"`
}

// Report writes the scan result as JSON
func (r *JSONReporter) Report(result *analyzer.ScanResult) error {
	bySeverity := make(map[string]int)
	for sev, count := range result.Summary.BySeverity {
		bySeverity[sev.String()] = count
	}

	byCategory := make(map[string]int)
	for cat, count := range result.Summary.ByCategory {
		byCategory[cat.String()] = count
	}

	issues := make([]JSONIssue, len(result.Issues))
	for i, issue := range result.Issues {
		issues[i] = JSONIssue{
			ID:          issue.RuleID,
			Name:        issue.RuleName,
			Severity:    issue.Severity.String(),
			Category:    issue.Category.String(),
			Tags:        issue.Tags,
			Unit:        issue.Unit,
			File:        issue.File,
			Line:        issue.Line,
			Description: issue.Description,
			Suggestion:  issue.Suggestion,
			References:  issue.References,
		}
	}

	output := JSONOutput{
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary: JSONSummary{
			TotalUnits:   result.Summary.TotalUnits,
			TotalIssues:  result.Summary.TotalIssues,
			RulesChecked: result.Summary.RulesChecked,
			BySeverity:   bySeverity,
			ByCategory:   byCategory,
		},
		Issues: issues,
	}

	encoder := json.NewEncoder(r.w)
	if r.pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(output)
}
