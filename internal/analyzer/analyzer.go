package analyzer

import (
	"fmt"
	"os"
	"sort"

	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

// Analyzer orchestrates the scanning of systemd units
type Analyzer struct {
	config    *rules.Config
	unitPaths []string
}

// Options configures the analyzer
type Options struct {
	UnitPaths   []string
	Config      *rules.Config
	Category    *types.Category
	MinSeverity *types.Severity
	Tags        []string
}

// New creates a new Analyzer with the given options
func New(opts Options) *Analyzer {
	paths := opts.UnitPaths
	if len(paths) == 0 {
		paths = DefaultUnitPaths()
	}

	config := opts.Config
	if config == nil {
		config = rules.DefaultConfig()
	}

	return &Analyzer{
		config:    config,
		unitPaths: paths,
	}
}

// ScanResult contains the results of a scan
type ScanResult struct {
	Units   []*types.UnitFile
	Issues  []types.Issue
	Summary Summary
}

// Summary provides aggregate statistics
type Summary struct {
	TotalUnits   int
	TotalIssues  int
	BySeverity   map[types.Severity]int
	ByCategory   map[types.Category]int
	RulesChecked int
}

// Scan performs a full system audit
func (a *Analyzer) Scan(opts Options) (*ScanResult, error) {
	allUnits, err := LoadUnitsFromPaths(a.unitPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load units: %w", err)
	}

	if len(allUnits) == 0 {
		return &ScanResult{
			Summary: Summary{
				BySeverity: make(map[types.Severity]int),
				ByCategory: make(map[types.Category]int),
			},
		}, nil
	}

	var allIssues []types.Issue
	var units []*types.UnitFile

	for _, unit := range allUnits {
		units = append(units, unit)

		ctx := rules.NewContextWithUnits(unit, allUnits)
		ctx.Config = a.config

		var issues []types.Issue
		if opts.Category != nil || opts.MinSeverity != nil || len(opts.Tags) > 0 {
			issues = rules.RunFiltered(ctx, opts.Category, opts.MinSeverity, opts.Tags)
		} else {
			issues = rules.RunAll(ctx)
		}

		allIssues = append(allIssues, issues...)
	}

	sort.Slice(units, func(i, j int) bool {
		return units[i].Name < units[j].Name
	})

	sort.Slice(allIssues, func(i, j int) bool {
		if allIssues[i].Severity != allIssues[j].Severity {
			return allIssues[i].Severity > allIssues[j].Severity
		}
		return allIssues[i].Unit < allIssues[j].Unit
	})

	summary := Summary{
		TotalUnits:   len(units),
		TotalIssues:  len(allIssues),
		BySeverity:   make(map[types.Severity]int),
		ByCategory:   make(map[types.Category]int),
		RulesChecked: rules.Count(),
	}

	for _, issue := range allIssues {
		summary.BySeverity[issue.Severity]++
		summary.ByCategory[issue.Category]++
	}

	return &ScanResult{
		Units:   units,
		Issues:  allIssues,
		Summary: summary,
	}, nil
}

// CheckFiles checks specific unit files
func (a *Analyzer) CheckFiles(paths []string, opts Options) (*ScanResult, error) {
	allUnits := make(map[string]*types.UnitFile)
	var units []*types.UnitFile

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("cannot access %s: %w", path, err)
		}

		if info.IsDir() {
			dirUnits, err := LoadUnitsFromDirectory(path)
			if err != nil {
				return nil, fmt.Errorf("failed to load units from %s: %w", path, err)
			}
			for name, unit := range dirUnits {
				allUnits[name] = unit
				units = append(units, unit)
			}
		} else {
			unit, err := ParseUnitFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", path, err)
			}
			allUnits[unit.Name] = unit
			units = append(units, unit)
		}
	}

	var allIssues []types.Issue

	for _, unit := range units {
		ctx := rules.NewContextWithUnits(unit, allUnits)
		ctx.Config = a.config

		var issues []types.Issue
		if opts.Category != nil || opts.MinSeverity != nil || len(opts.Tags) > 0 {
			issues = rules.RunFiltered(ctx, opts.Category, opts.MinSeverity, opts.Tags)
		} else {
			issues = rules.RunAll(ctx)
		}

		allIssues = append(allIssues, issues...)
	}

	sort.Slice(allIssues, func(i, j int) bool {
		if allIssues[i].Severity != allIssues[j].Severity {
			return allIssues[i].Severity > allIssues[j].Severity
		}
		return allIssues[i].Unit < allIssues[j].Unit
	})

	summary := Summary{
		TotalUnits:   len(units),
		TotalIssues:  len(allIssues),
		BySeverity:   make(map[types.Severity]int),
		ByCategory:   make(map[types.Category]int),
		RulesChecked: rules.Count(),
	}

	for _, issue := range allIssues {
		summary.BySeverity[issue.Severity]++
		summary.ByCategory[issue.Category]++
	}

	return &ScanResult{
		Units:   units,
		Issues:  allIssues,
		Summary: summary,
	}, nil
}
