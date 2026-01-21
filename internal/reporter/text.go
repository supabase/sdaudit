package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/samrose/sdaudit/internal/analyzer"
	"github.com/samrose/sdaudit/pkg/types"
)

// TextReporter outputs scan results in human-readable format
type TextReporter struct {
	w        io.Writer
	useColor bool
}

// NewTextReporter creates a new text reporter
func NewTextReporter(w io.Writer, useColor bool) *TextReporter {
	return &TextReporter{w: w, useColor: useColor}
}

// Report writes the scan result to the output
//
//nolint:errcheck // Output errors are not actionable for a text reporter
func (r *TextReporter) Report(result *analyzer.ScanResult) error {
	fmt.Fprintf(r.w, "\n%s\n", r.bold("sdaudit scan results"))
	fmt.Fprintf(r.w, "%s\n\n", strings.Repeat("=", 50))

	fmt.Fprintf(r.w, "Units scanned: %d\n", result.Summary.TotalUnits)
	fmt.Fprintf(r.w, "Rules checked: %d\n", result.Summary.RulesChecked)
	fmt.Fprintf(r.w, "Issues found:  %d\n\n", result.Summary.TotalIssues)

	if result.Summary.TotalIssues > 0 {
		fmt.Fprintf(r.w, "%s\n", r.bold("By Severity:"))
		for _, sev := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
			if count := result.Summary.BySeverity[sev]; count > 0 {
				fmt.Fprintf(r.w, "  %s: %d\n", r.colorSeverity(sev), count)
			}
		}
		_, _ = fmt.Fprintln(r.w)

		fmt.Fprintf(r.w, "%s\n", r.bold("By Category:"))
		for _, cat := range []types.Category{types.CategorySecurity, types.CategoryReliability, types.CategoryPerformance, types.CategoryBestPractice} {
			if count := result.Summary.ByCategory[cat]; count > 0 {
				fmt.Fprintf(r.w, "  %s: %d\n", cat.String(), count)
			}
		}
		_, _ = fmt.Fprintln(r.w)
	}

	if len(result.Issues) > 0 {
		fmt.Fprintf(r.w, "%s\n", r.bold("Issues:"))
		fmt.Fprintf(r.w, "%s\n\n", strings.Repeat("-", 50))

		for i, issue := range result.Issues {
			r.printIssue(i+1, &issue)
		}
	} else {
		fmt.Fprintf(r.w, "%s\n", r.green("No issues found!"))
	}

	return nil
}

//nolint:errcheck // Output errors are not actionable for a text reporter
func (r *TextReporter) printIssue(num int, issue *types.Issue) {
	fmt.Fprintf(r.w, "%d. [%s] %s: %s\n", num, r.colorSeverity(issue.Severity), r.bold(issue.RuleID), issue.RuleName)
	fmt.Fprintf(r.w, "   Unit: %s\n", issue.Unit)
	if issue.File != "" {
		fmt.Fprintf(r.w, "   File: %s", issue.File)
		if issue.Line != nil {
			fmt.Fprintf(r.w, ":%d", *issue.Line)
		}
		_, _ = fmt.Fprintln(r.w)
	}
	fmt.Fprintf(r.w, "   %s\n", issue.Description)
	if issue.Suggestion != "" {
		fmt.Fprintf(r.w, "   %s %s\n", r.bold("Fix:"), issue.Suggestion)
	}
	if len(issue.References) > 0 {
		fmt.Fprintf(r.w, "   %s\n", r.bold("References:"))
		for _, ref := range issue.References {
			fmt.Fprintf(r.w, "     - %s\n", ref)
		}
	}
	_, _ = fmt.Fprintln(r.w)
}

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

func (r *TextReporter) bold(s string) string {
	if !r.useColor {
		return s
	}
	return colorBold + s + colorReset
}

func (r *TextReporter) green(s string) string {
	if !r.useColor {
		return s
	}
	return colorGreen + s + colorReset
}

func (r *TextReporter) colorSeverity(sev types.Severity) string {
	name := strings.ToUpper(sev.String())
	if !r.useColor {
		return name
	}
	switch sev {
	case types.SeverityCritical:
		return colorBold + colorRed + name + colorReset
	case types.SeverityHigh:
		return colorRed + name + colorReset
	case types.SeverityMedium:
		return colorYellow + name + colorReset
	case types.SeverityLow:
		return colorCyan + name + colorReset
	default:
		return colorGray + name + colorReset
	}
}
