package reliability

import (
	"strconv"
	"strings"

	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

func init() {
	rules.Register(&REL002{})
}

type REL002 struct{}

func (r *REL002) ID() string   { return "REL002" }
func (r *REL002) Name() string { return "RestartSec too short" }

func (r *REL002) Description() string {
	return "RestartSec should be at least 1 second to prevent restart loops."
}

func (r *REL002) Category() types.Category { return types.CategoryReliability }
func (r *REL002) Severity() types.Severity { return types.SeverityMedium }
func (r *REL002) Tags() []string           { return []string{"availability", "restart-loop"} }

func (r *REL002) Suggestion() string {
	return "Set 'RestartSec=1' or higher in the [Service] section."
}

func (r *REL002) References() []string {
	return []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html#RestartSec="}
}

func (r *REL002) Check(ctx *rules.Context) []types.Issue {
	unit := ctx.Unit
	if unit == nil || !unit.IsService() {
		return nil
	}

	restart := unit.GetDirective("Service", "Restart")
	if restart == "" || restart == "no" {
		return nil
	}

	restartSec := unit.GetDirective("Service", "RestartSec")
	if restartSec == "" {
		return nil
	}

	seconds := parseTimeValue(restartSec)
	minSec := ctx.Config.Thresholds.RestartSecMin
	if minSec == 0 {
		minSec = 1.0
	}

	if seconds < minSec {
		return []types.Issue{{
			RuleID:      r.ID(),
			RuleName:    r.Name(),
			Severity:    r.Severity(),
			Category:    r.Category(),
			Tags:        r.Tags(),
			Unit:        unit.Name,
			File:        unit.Path,
			Description: "RestartSec=" + restartSec + " may cause rapid restart loops.",
			Suggestion:  r.Suggestion(),
			References:  r.References(),
		}}
	}
	return nil
}

func parseTimeValue(s string) float64 {
	s = strings.TrimSpace(s)
	suffixes := []struct {
		suffix string
		mult   float64
	}{
		{"ms", 0.001}, {"msec", 0.001},
		{"s", 1}, {"sec", 1},
		{"m", 60}, {"min", 60},
		{"h", 3600}, {"hr", 3600},
	}

	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf.suffix) {
			if val, err := strconv.ParseFloat(strings.TrimSuffix(s, suf.suffix), 64); err == nil {
				return val * suf.mult
			}
		}
	}
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		return val
	}
	return 0
}
