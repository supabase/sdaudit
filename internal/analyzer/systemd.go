package analyzer

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// BootAnalysis contains the results of boot time analysis
type BootAnalysis struct {
	TotalTime     time.Duration
	KernelTime    time.Duration
	InitrdTime    time.Duration
	UserspaceTime time.Duration
	Units         []UnitTiming
	CriticalChain []ChainLink
	Issues        []BootIssue
}

// UnitTiming represents timing data for a single unit
type UnitTiming struct {
	Name     string
	Time     time.Duration
	Position int
}

// ChainLink represents a unit in the critical boot chain
type ChainLink struct {
	Name       string
	Time       time.Duration
	ActiveAt   time.Duration
	IsCritical bool
}

// BootIssue represents a detected boot issue
type BootIssue struct {
	Unit        string
	Description string
	Severity    string
	Suggestion  string
}

// AnalyzeBoot runs boot analysis using systemd-analyze
func AnalyzeBoot() (*BootAnalysis, error) {
	analysis := &BootAnalysis{}

	// Get overall boot time
	if err := analysis.parseBootTime(); err != nil {
		return nil, fmt.Errorf("failed to get boot time: %w", err)
	}

	// Get blame (unit timing)
	if err := analysis.parseBlame(); err != nil {
		return nil, fmt.Errorf("failed to get blame: %w", err)
	}

	// Get critical chain
	if err := analysis.parseCriticalChain(); err != nil {
		return nil, fmt.Errorf("failed to get critical-chain: %w", err)
	}

	// Analyze for issues
	analysis.detectIssues()

	return analysis, nil
}

// parseBootTime parses the output of systemd-analyze
func (a *BootAnalysis) parseBootTime() error {
	cmd := exec.Command("systemd-analyze")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Parse: "Startup finished in 2.5s (kernel) + 5.2s (initrd) + 45.3s (userspace) = 53.0s"
	// Or: "Startup finished in 2.5s (kernel) + 45.3s (userspace) = 47.8s"
	line := string(bytes.TrimSpace(output))

	// Extract times using regex
	kernelRe := regexp.MustCompile(`([\d.]+)s \(kernel\)`)
	initrdRe := regexp.MustCompile(`([\d.]+)s \(initrd\)`)
	userspaceRe := regexp.MustCompile(`([\d.]+)s \(userspace\)`)
	totalRe := regexp.MustCompile(`= ([\d.]+)s`)

	if matches := kernelRe.FindStringSubmatch(line); len(matches) > 1 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			a.KernelTime = time.Duration(secs * float64(time.Second))
		}
	}

	if matches := initrdRe.FindStringSubmatch(line); len(matches) > 1 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			a.InitrdTime = time.Duration(secs * float64(time.Second))
		}
	}

	if matches := userspaceRe.FindStringSubmatch(line); len(matches) > 1 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			a.UserspaceTime = time.Duration(secs * float64(time.Second))
		}
	}

	if matches := totalRe.FindStringSubmatch(line); len(matches) > 1 {
		if secs, err := strconv.ParseFloat(matches[1], 64); err == nil {
			a.TotalTime = time.Duration(secs * float64(time.Second))
		}
	}

	return nil
}

// parseBlame parses systemd-analyze blame output
func (a *BootAnalysis) parseBlame() error {
	cmd := exec.Command("systemd-analyze", "blame")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	position := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse: "  45.234s nginx.service"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		duration := parseDuration(parts[0])
		unit := parts[1]

		a.Units = append(a.Units, UnitTiming{
			Name:     unit,
			Time:     duration,
			Position: position,
		})
		position++
	}

	return scanner.Err()
}

// parseCriticalChain parses systemd-analyze critical-chain output
func (a *BootAnalysis) parseCriticalChain() error {
	cmd := exec.Command("systemd-analyze", "critical-chain")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse lines like:
		// "@45.234s" or "unit.service @12.345s +5.678s"
		// The @time is when it activated, +time is how long it took

		// Skip header lines
		if strings.HasPrefix(line, "The time") || strings.HasPrefix(line, "graphical.target") {
			continue
		}

		link := ChainLink{}

		// Extract unit name (before @)
		atIdx := strings.Index(line, "@")
		if atIdx > 0 {
			// Get unit name from the beginning (strip tree characters)
			unitPart := strings.TrimLeft(line[:atIdx], "│├└─ \t")
			link.Name = strings.TrimSpace(unitPart)
		}

		// Extract activation time (@X.XXXs)
		atRe := regexp.MustCompile(`@([\d.]+)(ms|s)`)
		if matches := atRe.FindStringSubmatch(line); len(matches) > 2 {
			link.ActiveAt = parseDuration(matches[1] + matches[2])
		}

		// Extract duration (+X.XXXs)
		plusRe := regexp.MustCompile(`\+([\d.]+)(ms|s)`)
		if matches := plusRe.FindStringSubmatch(line); len(matches) > 2 {
			link.Time = parseDuration(matches[1] + matches[2])
			// Mark as critical if it took significant time
			link.IsCritical = link.Time > 5*time.Second
		}

		if link.Name != "" {
			a.CriticalChain = append(a.CriticalChain, link)
		}
	}

	return scanner.Err()
}

// detectIssues analyzes the boot data for issues
func (a *BootAnalysis) detectIssues() {
	// Check for slow units (>5s)
	for _, unit := range a.Units {
		if unit.Time > 5*time.Second {
			a.Issues = append(a.Issues, BootIssue{
				Unit:        unit.Name,
				Description: fmt.Sprintf("Takes %.1fs to start", unit.Time.Seconds()),
				Severity:    "medium",
				Suggestion:  "Consider optimizing startup or using socket activation",
			})
		}
	}

	// Check critical chain for slow units
	for _, link := range a.CriticalChain {
		if link.IsCritical {
			a.Issues = append(a.Issues, BootIssue{
				Unit:        link.Name,
				Description: fmt.Sprintf("In critical chain, takes %.1fs", link.Time.Seconds()),
				Severity:    "high",
				Suggestion:  "This unit blocks boot progress - optimize or defer",
			})
		}
	}

	// Check for overall slow boot
	if a.UserspaceTime > 30*time.Second {
		a.Issues = append(a.Issues, BootIssue{
			Unit:        "system",
			Description: fmt.Sprintf("Userspace boot takes %.1fs", a.UserspaceTime.Seconds()),
			Severity:    "medium",
			Suggestion:  "Review slow units and consider parallelization",
		})
	}
}

// parseDuration parses systemd time format (e.g., "45.234s", "123ms", "1min 2.345s")
func parseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)

	// Handle compound formats like "1min 2.345s"
	if strings.Contains(s, "min") {
		var total time.Duration
		parts := strings.Fields(s)
		for _, part := range parts {
			total += parseSingleDuration(part)
		}
		return total
	}

	return parseSingleDuration(s)
}

func parseSingleDuration(s string) time.Duration {
	s = strings.TrimSpace(s)

	if strings.HasSuffix(s, "ms") {
		if val, err := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64); err == nil {
			return time.Duration(val * float64(time.Millisecond))
		}
	}

	if strings.HasSuffix(s, "s") {
		if val, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64); err == nil {
			return time.Duration(val * float64(time.Second))
		}
	}

	if strings.HasSuffix(s, "min") {
		if val, err := strconv.ParseFloat(strings.TrimSuffix(s, "min"), 64); err == nil {
			return time.Duration(val * float64(time.Minute))
		}
	}

	return 0
}

// DependencyGraph represents the systemd dependency graph
type DependencyGraph struct {
	Units map[string]*DependencyNode
	Edges []DependencyEdge
}

// DependencyNode represents a unit in the dependency graph
type DependencyNode struct {
	Name     string
	Type     string // "service", "socket", "target", etc.
	State    string
	Requires []string
	Wants    []string
	After    []string
	Before   []string
}

// DependencyEdge represents a dependency relationship
type DependencyEdge struct {
	From string
	To   string
	Type string // "requires", "wants", "after", "before"
}

// DependencyIssue represents a detected dependency issue
type DependencyIssue struct {
	Units       []string
	Description string
	Severity    string
	Suggestion  string
}

// AnalyzeDeps analyzes systemd dependencies
func AnalyzeDeps(unitName string) (*DependencyGraph, []DependencyIssue, error) {
	graph := &DependencyGraph{
		Units: make(map[string]*DependencyNode),
	}
	var issues []DependencyIssue

	// Get dependency tree
	args := []string{"list-dependencies"}
	if unitName != "" {
		args = append(args, unitName)
	}
	args = append(args, "--all")

	cmd := exec.Command("systemctl", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list dependencies: %w", err)
	}

	// Parse the tree output
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Extract unit name from tree format
		unitName := strings.TrimLeft(line, "│├└─● \t")
		unitName = strings.TrimSpace(unitName)
		if unitName == "" {
			continue
		}

		// Remove state indicators like (running), (dead), etc.
		if idx := strings.Index(unitName, " "); idx > 0 {
			unitName = unitName[:idx]
		}

		if _, exists := graph.Units[unitName]; !exists {
			graph.Units[unitName] = &DependencyNode{Name: unitName}
		}
	}

	// Check for cycles using systemd-analyze verify
	cycleIssues := detectCycles()
	issues = append(issues, cycleIssues...)

	return graph, issues, nil
}

// detectCycles checks for circular dependencies
func detectCycles() []DependencyIssue {
	var issues []DependencyIssue

	cmd := exec.Command("systemd-analyze", "verify", "--man=no", "default.target")
	output, _ := cmd.CombinedOutput() // Ignore error, we check output for cycles

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "cycle") || strings.Contains(line, "circular") {
			issues = append(issues, DependencyIssue{
				Description: strings.TrimSpace(line),
				Severity:    "critical",
				Suggestion:  "Review and break the dependency cycle",
			})
		}
	}

	return issues
}

// SecurityScore represents a unit's security score
type SecurityScore struct {
	Unit     string
	Score    float64
	Exposure string // "SAFE", "OK", "MEDIUM", "EXPOSED", "UNSAFE"
	Checks   []SecurityCheck
}

// SecurityCheck represents an individual security check result
type SecurityCheck struct {
	Name        string
	Description string
	Result      string // "OK", "NA", "MEDIUM", "EXPOSED", "UNSAFE"
	Weight      float64
}

// AnalyzeSecurity runs security analysis on units
func AnalyzeSecurity(unitName string) ([]SecurityScore, error) {
	var scores []SecurityScore

	args := []string{"security"}
	if unitName != "" {
		args = append(args, unitName)
	}
	args = append(args, "--no-pager")

	cmd := exec.Command("systemd-analyze", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run security analysis: %w", err)
	}

	// Parse the security output
	scanner := bufio.NewScanner(bytes.NewReader(output))
	var currentUnit *SecurityScore

	for scanner.Scan() {
		line := scanner.Text()

		// Check for unit header line (ends with exposure score)
		// Format: "unit.service                    5.4 MEDIUM"
		if strings.HasSuffix(line, "SAFE") || strings.HasSuffix(line, "OK") ||
			strings.HasSuffix(line, "MEDIUM") || strings.HasSuffix(line, "EXPOSED") ||
			strings.HasSuffix(line, "UNSAFE") {

			fields := strings.Fields(line)
			if len(fields) >= 3 {
				score := SecurityScore{
					Unit:     fields[0],
					Exposure: fields[len(fields)-1],
				}
				if val, err := strconv.ParseFloat(fields[len(fields)-2], 64); err == nil {
					score.Score = val
				}
				scores = append(scores, score)
				currentUnit = &scores[len(scores)-1]
			}
			continue
		}

		// TODO: Parse individual checks if we have a current unit
		// Format: "  ✓ PrivateTmp=                                   yes"
		// or:     "  ✗ NoNewPrivileges=                              no"
		// For now, we just capture the summary scores
		_ = currentUnit
	}

	return scores, scanner.Err()
}
