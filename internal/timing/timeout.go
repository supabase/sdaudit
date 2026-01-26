// Package timing provides timeout and critical path analysis for systemd units.
package timing

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/supabase/sdaudit/pkg/types"
)

// Default timeout values from systemd.
// Names intentionally match systemd directive names (TimeoutStartSec, etc.).
//
//nolint:staticcheck // ST1011: names match systemd directives
const (
	DefaultTimeoutStartSec = 90 * time.Second
	DefaultTimeoutStopSec  = 90 * time.Second
	DefaultRestartSec      = 100 * time.Millisecond
	DefaultJobTimeoutSec   = 0 // infinity
)

// TimeoutConfig holds parsed timeout values for a unit.
// Field names match systemd directive names for clarity.
//
//nolint:staticcheck // ST1011: names match systemd directives
type TimeoutConfig struct {
	Unit            string
	TimeoutStartSec time.Duration
	TimeoutStopSec  time.Duration
	TimeoutAbortSec time.Duration // Defaults to TimeoutStopSec
	JobTimeoutSec   time.Duration // 0 = infinity
	RestartSec      time.Duration
	Source          string // File where primary timeout is defined
}

// SystemConfig holds system-wide defaults from system.conf.
// Field names match systemd directive names for clarity.
//
//nolint:staticcheck // ST1011: names match systemd directives
type SystemConfig struct {
	DefaultTimeoutStartSec time.Duration
	DefaultTimeoutStopSec  time.Duration
	DefaultRestartSec      time.Duration
}

// DefaultSystemConfig returns systemd's default system configuration.
func DefaultSystemConfig() *SystemConfig {
	return &SystemConfig{
		DefaultTimeoutStartSec: DefaultTimeoutStartSec,
		DefaultTimeoutStopSec:  DefaultTimeoutStopSec,
		DefaultRestartSec:      DefaultRestartSec,
	}
}

// ParseTimeouts extracts timeout configuration from a unit.
// Falls back to system defaults if not specified.
func ParseTimeouts(unit *types.UnitFile, systemConf *SystemConfig) TimeoutConfig {
	if systemConf == nil {
		systemConf = DefaultSystemConfig()
	}

	config := TimeoutConfig{
		Unit:            unit.Name,
		TimeoutStartSec: systemConf.DefaultTimeoutStartSec,
		TimeoutStopSec:  systemConf.DefaultTimeoutStopSec,
		RestartSec:      systemConf.DefaultRestartSec,
		JobTimeoutSec:   0, // infinity
		Source:          unit.Path,
	}

	// Parse Service section timeouts
	if serviceSection, ok := unit.Sections["Service"]; ok {
		if val := getDirectiveValue(serviceSection, "TimeoutStartSec"); val != "" {
			if d, err := ParseDuration(val); err == nil {
				config.TimeoutStartSec = d
			}
		}

		if val := getDirectiveValue(serviceSection, "TimeoutStopSec"); val != "" {
			if d, err := ParseDuration(val); err == nil {
				config.TimeoutStopSec = d
			}
		}

		if val := getDirectiveValue(serviceSection, "TimeoutSec"); val != "" {
			// TimeoutSec sets both start and stop
			if d, err := ParseDuration(val); err == nil {
				config.TimeoutStartSec = d
				config.TimeoutStopSec = d
			}
		}

		if val := getDirectiveValue(serviceSection, "TimeoutAbortSec"); val != "" {
			if d, err := ParseDuration(val); err == nil {
				config.TimeoutAbortSec = d
			}
		}

		if val := getDirectiveValue(serviceSection, "RestartSec"); val != "" {
			if d, err := ParseDuration(val); err == nil {
				config.RestartSec = d
			}
		}
	}

	// Parse Unit section job timeout
	if unitSection, ok := unit.Sections["Unit"]; ok {
		if val := getDirectiveValue(unitSection, "JobTimeoutSec"); val != "" {
			if d, err := ParseDuration(val); err == nil {
				config.JobTimeoutSec = d
			}
		}

		if val := getDirectiveValue(unitSection, "JobRunningTimeoutSec"); val != "" {
			if d, err := ParseDuration(val); err == nil {
				// JobRunningTimeoutSec is similar to JobTimeoutSec
				if config.JobTimeoutSec == 0 {
					config.JobTimeoutSec = d
				}
			}
		}
	}

	// TimeoutAbortSec defaults to TimeoutStopSec
	if config.TimeoutAbortSec == 0 {
		config.TimeoutAbortSec = config.TimeoutStopSec
	}

	return config
}

// ParseAllTimeouts parses timeout configurations for all units.
func ParseAllTimeouts(units map[string]*types.UnitFile, systemConf *SystemConfig) map[string]TimeoutConfig {
	result := make(map[string]TimeoutConfig)
	for name, unit := range units {
		result[name] = ParseTimeouts(unit, systemConf)
	}
	return result
}

// getDirectiveValue gets the first value for a directive in a section.
func getDirectiveValue(section *types.Section, key string) string {
	if directives, ok := section.Directives[key]; ok && len(directives) > 0 {
		return directives[0].Value
	}
	return ""
}

// ParseDuration parses a systemd time span into a Go duration.
// Supports formats like: 5, 5s, 5min, 5h, 1h30min, "infinity"
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)

	// Handle special values
	if s == "" || s == "infinity" || s == "0" {
		return 0, nil
	}

	// If it's just a number, treat as seconds
	if num, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(num * float64(time.Second)), nil
	}

	// Parse complex duration strings
	return parseSystemdTimeSpan(s)
}

// parseSystemdTimeSpan parses systemd time span format.
// Examples: 5s, 5min, 5h, 1h30min, 5us, 5ms
func parseSystemdTimeSpan(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	var total time.Duration

	// Pattern to match number followed by unit
	re := regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(usec|us|msec|ms|seconds?|sec|s|minutes?|min|m|hours?|hr|h|days?|d|weeks?|w|months?|M|years?|y)?`)

	matches := re.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		// Try parsing as Go duration
		return time.ParseDuration(s)
	}

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		numStr := match[1]
		unit := ""
		if len(match) > 2 {
			unit = match[2]
		}

		num, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			continue
		}

		var multiplier time.Duration
		switch strings.ToLower(unit) {
		case "usec", "us":
			multiplier = time.Microsecond
		case "msec", "ms":
			multiplier = time.Millisecond
		case "seconds", "second", "sec", "s", "":
			multiplier = time.Second
		case "minutes", "minute", "min", "m":
			multiplier = time.Minute
		case "hours", "hour", "hr", "h":
			multiplier = time.Hour
		case "days", "day", "d":
			multiplier = 24 * time.Hour
		case "weeks", "week", "w":
			multiplier = 7 * 24 * time.Hour
		case "months", "month":
			// Approximate month as 30 days
			multiplier = 30 * 24 * time.Hour
		case "years", "year", "y":
			// Approximate year as 365 days
			multiplier = 365 * 24 * time.Hour
		default:
			multiplier = time.Second
		}

		total += time.Duration(num * float64(multiplier))
	}

	return total, nil
}

// FormatDuration formats a duration in a human-readable way.
func FormatDuration(d time.Duration) string {
	if d == 0 {
		return "infinity"
	}

	if d < time.Second {
		return d.String()
	}

	// Round to seconds for cleaner output
	d = d.Round(time.Second)
	return d.String()
}
