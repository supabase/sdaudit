package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/supabase/sdaudit/internal/analyzer"
	"github.com/supabase/sdaudit/internal/reporter"
	"github.com/supabase/sdaudit/internal/rules"
	"github.com/supabase/sdaudit/internal/tui"
	"github.com/supabase/sdaudit/pkg/types"

	// Import rule packages to trigger init() registration
	_ "github.com/supabase/sdaudit/internal/rules/bestpractice"
	_ "github.com/supabase/sdaudit/internal/rules/performance"
	_ "github.com/supabase/sdaudit/internal/rules/reliability"
	_ "github.com/supabase/sdaudit/internal/rules/security"
)

var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:     "sdaudit",
	Short:   "Comprehensive systemd auditing tool",
	Long:    `sdaudit analyzes systemd unit files and system configuration to detect misconfigurations, security issues, and performance problems.`,
	Version: version,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a full system audit",
	Long:  `Scan all systemd units and system configuration for issues.`,
	RunE:  runScan,
}

var checkCmd = &cobra.Command{
	Use:   "check [unit-files...]",
	Short: "Check specific unit file(s)",
	Long:  `Validate one or more systemd unit files for issues.`,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runCheck,
}

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all available rules",
	RunE:  runListRules,
}

var bootCmd = &cobra.Command{
	Use:   "boot",
	Short: "Analyze boot time",
	Long:  `Analyze systemd boot time using systemd-analyze blame and critical-chain.`,
	RunE:  runBoot,
}

var depsCmd = &cobra.Command{
	Use:   "deps [unit]",
	Short: "Analyze dependencies",
	Long:  `Analyze systemd unit dependencies and detect issues like circular dependencies.`,
	RunE:  runDeps,
}

var securityCmd = &cobra.Command{
	Use:   "security [unit]",
	Short: "Security scoring",
	Long:  `Run security analysis on systemd units using systemd-analyze security.`,
	RunE:  runSecurity,
}

func init() {
	rootCmd.PersistentFlags().StringP("format", "f", "text", "Output format: text, json, sarif")
	rootCmd.PersistentFlags().StringP("severity", "s", "info", "Minimum severity: critical, high, medium, low, info")
	rootCmd.PersistentFlags().StringP("category", "c", "", "Filter by category: security, performance, reliability, bestpractice")
	rootCmd.PersistentFlags().StringP("tags", "t", "", "Filter by tags (comma-separated)")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")

	scanCmd.Flags().Bool("tui", false, "Launch interactive TUI after scan")
	checkCmd.Flags().Bool("tui", false, "Launch interactive TUI after check")
	depsCmd.Flags().String("save", "", "Save dependency graph to file")
	depsCmd.Flags().String("diff", "", "Compare against baseline file")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(listRulesCmd)
	rootCmd.AddCommand(bootCmd)
	rootCmd.AddCommand(depsCmd)
	rootCmd.AddCommand(securityCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	severity, _ := cmd.Flags().GetString("severity")
	category, _ := cmd.Flags().GetString("category")
	tagsStr, _ := cmd.Flags().GetString("tags")
	noColor, _ := cmd.Flags().GetBool("no-color")
	useTUI, _ := cmd.Flags().GetBool("tui")

	opts := buildOptions(severity, category, tagsStr)

	a := analyzer.New(opts)
	result, err := a.Scan(opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if useTUI {
		return tui.Run(result)
	}

	return outputResult(result, format, noColor)
}

func runCheck(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	severity, _ := cmd.Flags().GetString("severity")
	category, _ := cmd.Flags().GetString("category")
	tagsStr, _ := cmd.Flags().GetString("tags")
	noColor, _ := cmd.Flags().GetBool("no-color")
	useTUI, _ := cmd.Flags().GetBool("tui")

	opts := buildOptions(severity, category, tagsStr)

	a := analyzer.New(opts)
	result, err := a.CheckFiles(args, opts)
	if err != nil {
		return fmt.Errorf("check failed: %w", err)
	}

	if useTUI {
		return tui.Run(result)
	}

	return outputResult(result, format, noColor)
}

func runListRules(cmd *cobra.Command, args []string) error {
	allRules := rules.All()

	fmt.Printf("\nRegistered Rules: %d\n", len(allRules))
	fmt.Println(strings.Repeat("=", 60))

	currentCategory := types.Category(-1)
	for _, rule := range allRules {
		if rule.Category() != currentCategory {
			currentCategory = rule.Category()
			fmt.Printf("\n[%s]\n", strings.ToUpper(currentCategory.String()))
		}
		fmt.Printf("  %-8s %-10s %s\n", rule.ID(), "["+rule.Severity().String()+"]", rule.Name())
	}
	fmt.Println()
	return nil
}

func runBoot(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	analysis, err := analyzer.AnalyzeBoot()
	if err != nil {
		return fmt.Errorf("boot analysis failed: %w", err)
	}

	switch format {
	case "json":
		return outputBootJSON(analysis)
	default:
		return outputBootText(analysis, !noColor)
	}
}

func outputBootJSON(analysis *analyzer.BootAnalysis) error {
	type JSONBootOutput struct {
		TotalTime     string                `json:"total_time"`
		KernelTime    string                `json:"kernel_time"`
		InitrdTime    string                `json:"initrd_time"`
		UserspaceTime string                `json:"userspace_time"`
		TopUnits      []analyzer.UnitTiming `json:"top_units"`
		CriticalChain []analyzer.ChainLink  `json:"critical_chain"`
		Issues        []analyzer.BootIssue  `json:"issues"`
	}

	// Get top 10 slowest units
	topUnits := analysis.Units
	if len(topUnits) > 10 {
		topUnits = topUnits[:10]
	}

	output := JSONBootOutput{
		TotalTime:     analysis.TotalTime.String(),
		KernelTime:    analysis.KernelTime.String(),
		InitrdTime:    analysis.InitrdTime.String(),
		UserspaceTime: analysis.UserspaceTime.String(),
		TopUnits:      topUnits,
		CriticalChain: analysis.CriticalChain,
		Issues:        analysis.Issues,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func outputBootText(analysis *analyzer.BootAnalysis, color bool) error {
	fmt.Println("\nBoot Time Analysis")
	fmt.Println(strings.Repeat("=", 50))

	fmt.Printf("\nTotal:     %s\n", analysis.TotalTime)
	fmt.Printf("Kernel:    %s\n", analysis.KernelTime)
	if analysis.InitrdTime > 0 {
		fmt.Printf("Initrd:    %s\n", analysis.InitrdTime)
	}
	fmt.Printf("Userspace: %s\n", analysis.UserspaceTime)

	fmt.Println("\nSlowest Units (blame):")
	fmt.Println(strings.Repeat("-", 50))
	count := 10
	if len(analysis.Units) < count {
		count = len(analysis.Units)
	}
	for i := 0; i < count; i++ {
		unit := analysis.Units[i]
		fmt.Printf("  %10s  %s\n", unit.Time, unit.Name)
	}

	if len(analysis.CriticalChain) > 0 {
		fmt.Println("\nCritical Chain:")
		fmt.Println(strings.Repeat("-", 50))
		for _, link := range analysis.CriticalChain {
			marker := " "
			if link.IsCritical {
				marker = "!"
			}
			fmt.Printf("  %s @%s +%s  %s\n", marker, link.ActiveAt, link.Time, link.Name)
		}
	}

	if len(analysis.Issues) > 0 {
		fmt.Println("\nIssues Detected:")
		fmt.Println(strings.Repeat("-", 50))
		for _, issue := range analysis.Issues {
			fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(issue.Severity), issue.Unit, issue.Description)
			fmt.Printf("          Suggestion: %s\n", issue.Suggestion)
		}
	}

	fmt.Println()
	return nil
}

func runDeps(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	var unitName string
	if len(args) > 0 {
		unitName = args[0]
	}

	graph, issues, err := analyzer.AnalyzeDeps(unitName)
	if err != nil {
		return fmt.Errorf("dependency analysis failed: %w", err)
	}

	switch format {
	case "json":
		return outputDepsJSON(graph, issues)
	default:
		return outputDepsText(graph, issues, unitName, !noColor)
	}
}

func outputDepsJSON(graph *analyzer.DependencyGraph, issues []analyzer.DependencyIssue) error {
	output := struct {
		UnitCount int                        `json:"unit_count"`
		Units     []string                   `json:"units"`
		Issues    []analyzer.DependencyIssue `json:"issues"`
	}{
		UnitCount: len(graph.Units),
		Issues:    issues,
	}

	for name := range graph.Units {
		output.Units = append(output.Units, name)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func outputDepsText(graph *analyzer.DependencyGraph, issues []analyzer.DependencyIssue, unitName string, color bool) error {
	fmt.Println("\nDependency Analysis")
	fmt.Println(strings.Repeat("=", 50))

	if unitName != "" {
		fmt.Printf("\nAnalyzing: %s\n", unitName)
	}

	fmt.Printf("\nTotal units in dependency tree: %d\n", len(graph.Units))

	if len(issues) > 0 {
		fmt.Println("\nIssues Detected:")
		fmt.Println(strings.Repeat("-", 50))
		for _, issue := range issues {
			fmt.Printf("  [%s] %s\n", strings.ToUpper(issue.Severity), issue.Description)
			if issue.Suggestion != "" {
				fmt.Printf("          Suggestion: %s\n", issue.Suggestion)
			}
		}
	} else {
		fmt.Println("\nNo dependency issues detected.")
	}

	fmt.Println()
	return nil
}

func runSecurity(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	var unitName string
	if len(args) > 0 {
		unitName = args[0]
	}

	scores, err := analyzer.AnalyzeSecurity(unitName)
	if err != nil {
		return fmt.Errorf("security analysis failed: %w", err)
	}

	switch format {
	case "json":
		return outputSecurityJSON(scores)
	default:
		return outputSecurityText(scores, !noColor)
	}
}

func outputSecurityJSON(scores []analyzer.SecurityScore) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(scores)
}

func outputSecurityText(scores []analyzer.SecurityScore, color bool) error {
	fmt.Println("\nSecurity Analysis")
	fmt.Println(strings.Repeat("=", 50))

	if len(scores) == 0 {
		fmt.Println("\nNo services analyzed.")
		fmt.Println()
		return nil
	}

	// Count by exposure level
	counts := make(map[string]int)
	var highRisk []analyzer.SecurityScore

	for _, score := range scores {
		counts[score.Exposure]++
		if score.Score > 5.0 {
			highRisk = append(highRisk, score)
		}
	}

	fmt.Printf("\nTotal services analyzed: %d\n", len(scores))
	fmt.Println("\nExposure Summary:")
	for _, level := range []string{"UNSAFE", "EXPOSED", "MEDIUM", "OK", "SAFE"} {
		if counts[level] > 0 {
			fmt.Printf("  %-8s  %d\n", level, counts[level])
		}
	}

	if len(highRisk) > 0 {
		fmt.Println("\nHigh Risk Services (score > 5.0):")
		fmt.Println(strings.Repeat("-", 50))
		for _, score := range highRisk {
			fmt.Printf("  %.1f %-8s  %s\n", score.Score, score.Exposure, score.Unit)
		}
	}

	fmt.Println()
	return nil
}

func buildOptions(severity, category, tagsStr string) analyzer.Options {
	opts := analyzer.Options{}

	if severity != "" && severity != "info" {
		sev := types.ParseSeverity(severity)
		opts.MinSeverity = &sev
	}

	if category != "" {
		cat := types.ParseCategory(category)
		opts.Category = &cat
	}

	if tagsStr != "" {
		opts.Tags = strings.Split(tagsStr, ",")
		for i := range opts.Tags {
			opts.Tags[i] = strings.TrimSpace(opts.Tags[i])
		}
	}

	return opts
}

func outputResult(result *analyzer.ScanResult, format string, noColor bool) error {
	switch format {
	case "json":
		return reporter.NewJSONReporter(os.Stdout, true).Report(result)
	case "sarif":
		return reporter.NewSARIFReporter(os.Stdout, true).Report(result)
	default:
		return reporter.NewTextReporter(os.Stdout, !noColor).Report(result)
	}
}
