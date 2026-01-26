package timing

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/supabase/sdaudit/internal/graph"
	"github.com/supabase/sdaudit/pkg/types"
)

// CascadeRisk represents a potential timeout cascade.
type CascadeRisk struct {
	Unit           string
	CriticalPath   time.Duration // Time to reach this unit
	OwnTimeout     time.Duration // Unit's TimeoutStartSec
	Risk           string        // "critical", "high", "medium", "low"
	Description    string
	Recommendation string
	File           string
	Line           int
}

// CascadeResult contains all detected cascade risks.
type CascadeResult struct {
	Risks         []CascadeRisk
	TotalRisks    int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
}

// DetectCascades finds units where critical path may exceed timeout.
// Also detects:
// - network-online.target deps with tight timeouts
// - Long chains of serial dependencies
// - Restart loops where RestartSec + dependency start time > TimeoutStartSec
func DetectCascades(g *graph.Graph, paths CriticalPathResult, timeouts map[string]TimeoutConfig) CascadeResult {
	var risks []CascadeRisk

	// Detect critical path > own timeout
	risks = append(risks, detectPathTimeoutExceeded(g, paths, timeouts)...)

	// Detect network-online deps with tight timeouts
	risks = append(risks, detectNetworkDependencyRisks(g, timeouts)...)

	// Detect long serial chains
	risks = append(risks, detectLongChains(paths, timeouts)...)

	// Detect restart loop risks
	risks = append(risks, detectRestartLoopRisks(g, paths, timeouts)...)

	// Sort by risk level
	sort.Slice(risks, func(i, j int) bool {
		return riskOrder(risks[i].Risk) < riskOrder(risks[j].Risk)
	})

	// Count by severity
	result := CascadeResult{
		Risks:      risks,
		TotalRisks: len(risks),
	}
	for _, risk := range risks {
		switch risk.Risk {
		case "critical":
			result.CriticalCount++
		case "high":
			result.HighCount++
		case "medium":
			result.MediumCount++
		case "low":
			result.LowCount++
		}
	}

	return result
}

func riskOrder(risk string) int {
	switch risk {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// detectPathTimeoutExceeded finds units where critical path time exceeds their timeout.
func detectPathTimeoutExceeded(g *graph.Graph, paths CriticalPathResult, timeouts map[string]TimeoutConfig) []CascadeRisk {
	var risks []CascadeRisk

	for unitName, path := range paths.Paths {
		if len(path.Path) <= 1 {
			continue // No dependencies
		}

		tc, ok := timeouts[unitName]
		if !ok {
			continue
		}

		// Calculate time spent waiting for dependencies (exclude own timeout)
		depTime := path.TotalTime - tc.TimeoutStartSec

		// Check if job timeout would be exceeded
		// Job timeout starts when the job is created, not when the unit starts activating
		if tc.JobTimeoutSec > 0 && depTime > tc.JobTimeoutSec {
			risk := "critical"
			if depTime < tc.JobTimeoutSec*2 {
				risk = "high"
			}

			unit := g.Unit(unitName)
			file := ""
			line := 0
			if unit != nil {
				file = unit.Path
			}

			risks = append(risks, CascadeRisk{
				Unit:         unitName,
				CriticalPath: depTime,
				OwnTimeout:   tc.JobTimeoutSec,
				Risk:         risk,
				Description: fmt.Sprintf(
					"Critical path to %s takes %s, but JobTimeoutSec is %s. "+
						"The job may timeout waiting for dependencies.",
					unitName, FormatDuration(depTime), FormatDuration(tc.JobTimeoutSec)),
				Recommendation: "Increase JobTimeoutSec or reduce dependency chain length",
				File:           file,
				Line:           line,
			})
		}
	}

	return risks
}

// detectNetworkDependencyRisks finds units depending on network-online.target with tight timeouts.
func detectNetworkDependencyRisks(g *graph.Graph, timeouts map[string]TimeoutConfig) []CascadeRisk {
	var risks []CascadeRisk

	// Find all units that depend on network-online.target
	networkTargets := []string{
		"network-online.target",
		"network.target",
	}

	for _, unit := range g.Units() {
		edges := g.EdgesFrom(unit.Name)

		dependsOnNetwork := false
		var networkTarget string
		for _, edge := range edges {
			for _, nt := range networkTargets {
				if edge.To == nt && (edge.Type == graph.EdgeAfter || edge.Type == graph.EdgeRequires || edge.Type == graph.EdgeWants) {
					dependsOnNetwork = true
					networkTarget = nt
					break
				}
			}
		}

		if !dependsOnNetwork {
			continue
		}

		tc, ok := timeouts[unit.Name]
		if !ok {
			continue
		}

		// network-online.target can take 30+ seconds on slow networks
		// Flag units with timeouts < 30s
		if tc.TimeoutStartSec > 0 && tc.TimeoutStartSec < 30*time.Second {
			risk := "high"
			if tc.TimeoutStartSec < 10*time.Second {
				risk = "critical"
			} else if tc.TimeoutStartSec >= 20*time.Second {
				risk = "medium"
			}

			risks = append(risks, CascadeRisk{
				Unit:         unit.Name,
				CriticalPath: 0, // Unknown
				OwnTimeout:   tc.TimeoutStartSec,
				Risk:         risk,
				Description: fmt.Sprintf(
					"%s depends on %s but has TimeoutStartSec=%s. "+
						"Network initialization can take 30+ seconds on slow/unreliable networks.",
					unit.Name, networkTarget, FormatDuration(tc.TimeoutStartSec)),
				Recommendation: "Increase TimeoutStartSec to at least 60s for network-dependent services",
				File:           tc.Source,
			})
		}
	}

	return risks
}

// detectLongChains finds units with very long dependency chains.
func detectLongChains(paths CriticalPathResult, timeouts map[string]TimeoutConfig) []CascadeRisk {
	var risks []CascadeRisk

	// Flag chains longer than 10 units
	const longChainThreshold = 10
	const veryLongChainThreshold = 20

	for unitName, path := range paths.Paths {
		chainLen := len(path.Path)
		if chainLen < longChainThreshold {
			continue
		}

		tc := timeouts[unitName]

		risk := "low"
		if chainLen >= veryLongChainThreshold {
			risk = "medium"
		}

		risks = append(risks, CascadeRisk{
			Unit:         unitName,
			CriticalPath: path.TotalTime,
			OwnTimeout:   tc.TimeoutStartSec,
			Risk:         risk,
			Description: fmt.Sprintf(
				"%s has a dependency chain of %d units (critical path: %s). "+
					"Long chains increase boot time and timeout risk.",
				unitName, chainLen, FormatDuration(path.TotalTime)),
			Recommendation: "Review dependency chain for unnecessary ordering constraints",
			File:           tc.Source,
		})
	}

	return risks
}

// detectRestartLoopRisks finds units where restart timing could cause issues.
func detectRestartLoopRisks(g *graph.Graph, paths CriticalPathResult, timeouts map[string]TimeoutConfig) []CascadeRisk {
	var risks []CascadeRisk

	for _, unit := range g.Units() {
		if unit.Type != "service" {
			continue
		}

		tc, ok := timeouts[unit.Name]
		if !ok {
			continue
		}

		// Check if unit has Restart= enabled
		restartPolicy := unit.GetDirective("Service", "Restart")
		if restartPolicy == "" || restartPolicy == "no" {
			continue
		}

		// Get critical path time (time for dependencies to start)
		path, ok := paths.Paths[unit.Name]
		if !ok {
			continue
		}

		// Calculate total restart cycle time
		depTime := path.TotalTime - tc.TimeoutStartSec
		if depTime < 0 {
			depTime = 0
		}
		restartCycleTime := tc.RestartSec + depTime

		// If restart cycle time approaches or exceeds timeout, there's a risk
		if tc.TimeoutStartSec > 0 && restartCycleTime > tc.TimeoutStartSec/2 {
			risk := "low"
			if restartCycleTime >= tc.TimeoutStartSec {
				risk = "high"
			} else if restartCycleTime >= tc.TimeoutStartSec*3/4 {
				risk = "medium"
			}

			risks = append(risks, CascadeRisk{
				Unit:         unit.Name,
				CriticalPath: depTime,
				OwnTimeout:   tc.TimeoutStartSec,
				Risk:         risk,
				Description: fmt.Sprintf(
					"%s has Restart=%s with RestartSec=%s. "+
						"Dependency startup time (%s) + RestartSec = %s, which is %s of TimeoutStartSec (%s). "+
						"Rapid failures could exhaust timeout during restart cycles.",
					unit.Name, restartPolicy, FormatDuration(tc.RestartSec),
					FormatDuration(depTime), FormatDuration(restartCycleTime),
					formatPercent(restartCycleTime, tc.TimeoutStartSec),
					FormatDuration(tc.TimeoutStartSec)),
				Recommendation: "Increase TimeoutStartSec or reduce RestartSec/dependency chain",
				File:           tc.Source,
			})
		}
	}

	return risks
}

func formatPercent(a, b time.Duration) string {
	if b == 0 {
		return "N/A"
	}
	pct := float64(a) / float64(b) * 100
	return fmt.Sprintf("%.0f%%", pct)
}

// AnalyzeUnitTiming provides detailed timing analysis for a specific unit.
type UnitTimingAnalysis struct {
	Unit           string
	TimeoutConfig  TimeoutConfig
	CriticalPath   CriticalPath
	CascadeRisks   []CascadeRisk
	Dependencies   []string
	DependencyTime time.Duration
}

// AnalyzeUnit provides comprehensive timing analysis for a single unit.
func AnalyzeUnit(unitName string, g *graph.Graph, units map[string]*types.UnitFile, timeouts map[string]TimeoutConfig) *UnitTimingAnalysis {
	unit := g.Unit(unitName)
	if unit == nil {
		return nil
	}

	tc, ok := timeouts[unitName]
	if !ok {
		tc = TimeoutConfig{
			Unit:            unitName,
			TimeoutStartSec: DefaultTimeoutStartSec,
			TimeoutStopSec:  DefaultTimeoutStopSec,
			RestartSec:      DefaultRestartSec,
		}
	}

	paths := ComputeCriticalPaths(g, timeouts)
	path := paths.Paths[unitName]

	cascades := DetectCascades(g, paths, timeouts)
	var unitRisks []CascadeRisk
	for _, risk := range cascades.Risks {
		if risk.Unit == unitName {
			unitRisks = append(unitRisks, risk)
		}
	}

	// Get direct dependencies
	deps := g.EdgesFrom(unitName)
	var depNames []string
	for _, edge := range deps {
		if edge.Type == graph.EdgeAfter {
			depNames = append(depNames, edge.To)
		}
	}
	sort.Strings(depNames)

	// Calculate dependency time
	depTime := path.TotalTime - tc.TimeoutStartSec
	if depTime < 0 {
		depTime = 0
	}

	return &UnitTimingAnalysis{
		Unit:           unitName,
		TimeoutConfig:  tc,
		CriticalPath:   path,
		CascadeRisks:   unitRisks,
		Dependencies:   depNames,
		DependencyTime: depTime,
	}
}

// Summary returns a text summary of the timing analysis.
func (a *UnitTimingAnalysis) Summary() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Timing Analysis for %s\n", a.Unit))
	sb.WriteString(strings.Repeat("=", 40) + "\n\n")

	sb.WriteString("Timeout Configuration:\n")
	sb.WriteString(fmt.Sprintf("  TimeoutStartSec: %s\n", FormatDuration(a.TimeoutConfig.TimeoutStartSec)))
	sb.WriteString(fmt.Sprintf("  TimeoutStopSec:  %s\n", FormatDuration(a.TimeoutConfig.TimeoutStopSec)))
	sb.WriteString(fmt.Sprintf("  RestartSec:      %s\n", FormatDuration(a.TimeoutConfig.RestartSec)))
	if a.TimeoutConfig.JobTimeoutSec > 0 {
		sb.WriteString(fmt.Sprintf("  JobTimeoutSec:   %s\n", FormatDuration(a.TimeoutConfig.JobTimeoutSec)))
	}
	sb.WriteString("\n")

	sb.WriteString("Critical Path:\n")
	sb.WriteString(fmt.Sprintf("  Total time:      %s\n", FormatDuration(a.CriticalPath.TotalTime)))
	sb.WriteString(fmt.Sprintf("  Dependency time: %s\n", FormatDuration(a.DependencyTime)))
	sb.WriteString(fmt.Sprintf("  Path length:     %d units\n", len(a.CriticalPath.Path)))
	if a.CriticalPath.Bottleneck != "" {
		sb.WriteString(fmt.Sprintf("  Bottleneck:      %s\n", a.CriticalPath.Bottleneck))
	}
	sb.WriteString("\n")

	if len(a.CascadeRisks) > 0 {
		sb.WriteString("Cascade Risks:\n")
		for _, risk := range a.CascadeRisks {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(risk.Risk), risk.Description))
		}
	}

	return sb.String()
}
