package validation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// TimerValidation contains results of timer unit validation.
type TimerValidation struct {
	Unit              string
	MissingService    bool              // No matching .service or Unit=
	ServiceName       string            // The expected service name
	InvalidOnCalendar []InvalidCalendar // Malformed calendar expressions
	InvalidTimers     []InvalidTimer    // Invalid On*= directives
	NoTrigger         bool              // No On*= directives at all
	Issues            []string
	Valid             bool
}

// InvalidCalendar represents an invalid OnCalendar= expression.
type InvalidCalendar struct {
	Value  string
	Reason string
	Line   int
}

// InvalidTimer represents an invalid timer directive.
type InvalidTimer struct {
	Directive string
	Value     string
	Reason    string
	Line      int
}

// ValidateTimer checks timer unit configuration.
func ValidateTimer(unit *types.UnitFile, allUnits map[string]*types.UnitFile) TimerValidation {
	result := TimerValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	if unit.Type != "timer" {
		return result
	}

	timerSection, hasTimer := unit.Sections["Timer"]
	if !hasTimer {
		result.Valid = false
		result.Issues = append(result.Issues, "Timer unit has no [Timer] section")
		return result
	}

	// Determine expected service name
	serviceName := getTimerServiceName(unit, timerSection)
	result.ServiceName = serviceName

	// Check if service exists
	if _, exists := allUnits[serviceName]; !exists {
		result.MissingService = true
		result.Valid = false
	}

	// Check for trigger directives
	triggerDirectives := []string{
		"OnCalendar",
		"OnActiveSec",
		"OnBootSec",
		"OnStartupSec",
		"OnUnitActiveSec",
		"OnUnitInactiveSec",
	}

	hasTrigger := false
	for _, directive := range triggerDirectives {
		if dirs, ok := timerSection.Directives[directive]; ok && len(dirs) > 0 {
			hasTrigger = true

			for _, d := range dirs {
				if directive == "OnCalendar" {
					if invalid := validateCalendarExpression(d.Value, d.Line); invalid != nil {
						result.InvalidOnCalendar = append(result.InvalidOnCalendar, *invalid)
					}
				} else {
					if invalid := validateTimerExpression(directive, d.Value, d.Line); invalid != nil {
						result.InvalidTimers = append(result.InvalidTimers, *invalid)
					}
				}
			}
		}
	}

	if !hasTrigger {
		result.NoTrigger = true
		result.Valid = false
		result.Issues = append(result.Issues, "Timer unit has no trigger directives (OnCalendar, OnBootSec, etc.)")
	}

	if len(result.InvalidOnCalendar) > 0 || len(result.InvalidTimers) > 0 || len(result.Issues) > 0 {
		result.Valid = false
	}

	return result
}

// getTimerServiceName determines which service this timer activates.
func getTimerServiceName(unit *types.UnitFile, timerSection *types.Section) string {
	// Check explicit Unit= directive
	if service := getDirectiveValue(timerSection, "Unit"); service != "" {
		return service
	}

	// Default: same name with .service extension
	return strings.TrimSuffix(unit.Name, ".timer") + ".service"
}

// validateCalendarExpression validates an OnCalendar= expression.
// Full calendar spec: DOW YYYY-MM-DD HH:MM:SS
func validateCalendarExpression(value string, line int) *InvalidCalendar {
	value = strings.TrimSpace(value)
	if value == "" {
		return &InvalidCalendar{
			Value:  value,
			Reason: "Empty calendar expression",
			Line:   line,
		}
	}

	// Common predefined expressions
	predefined := map[string]bool{
		"minutely":     true,
		"hourly":       true,
		"daily":        true,
		"monthly":      true,
		"weekly":       true,
		"yearly":       true,
		"annually":     true,
		"quarterly":    true,
		"semiannually": true,
		"*-*-* *:*:*":  true,
	}

	if predefined[strings.ToLower(value)] {
		return nil
	}

	// Basic validation of calendar expression format
	// This is a simplified check - full validation would be complex

	// Check for obviously malformed expressions
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return &InvalidCalendar{
			Value:  value,
			Reason: "Empty calendar expression",
			Line:   line,
		}
	}

	// Valid day-of-week names
	validDOW := map[string]bool{
		"sun": true, "sunday": true,
		"mon": true, "monday": true,
		"tue": true, "tuesday": true,
		"wed": true, "wednesday": true,
		"thu": true, "thursday": true,
		"fri": true, "friday": true,
		"sat": true, "saturday": true,
	}

	// Check if first part is a day-of-week
	firstPart := strings.ToLower(strings.TrimSuffix(parts[0], ","))
	if validDOW[firstPart] || strings.Contains(firstPart, "..") {
		// Day of week component - skip to next
		parts = parts[1:]
	}

	// Be lenient with validation - systemd calendar expressions have many valid formats:
	// - Shorthands like "*-*-1" or "Mon *-*-* 10:00"
	// - Ranges, commas, and wildcards in date/time parts
	// We only do basic validation here, trusting systemd to report detailed errors
	_ = parts

	return nil
}

// validateTimerExpression validates On*Sec= directives.
func validateTimerExpression(directive, value string, line int) *InvalidTimer {
	value = strings.TrimSpace(value)
	if value == "" {
		return &InvalidTimer{
			Directive: directive,
			Value:     value,
			Reason:    "Empty value",
			Line:      line,
		}
	}

	// These accept time spans (like TimeoutSec)
	// Valid formats: 5, 5s, 5min, 5h, 1h30min

	// Try to parse as a simple number (seconds)
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return nil
	}

	// Check for time span format
	timeSpanRegex := regexp.MustCompile(`^\d+(\.\d+)?\s*(usec|us|msec|ms|seconds?|sec|s|minutes?|min|m|hours?|hr|h|days?|d|weeks?|w|months?|M|years?|y)?(\s+\d+(\.\d+)?\s*(usec|us|msec|ms|seconds?|sec|s|minutes?|min|m|hours?|hr|h|days?|d|weeks?|w|months?|M|years?|y)?)*$`)

	if !timeSpanRegex.MatchString(value) {
		return &InvalidTimer{
			Directive: directive,
			Value:     value,
			Reason:    fmt.Sprintf("Invalid time span format: %s", value),
			Line:      line,
		}
	}

	return nil
}

// ValidateAllTimers validates all timer units in a collection.
func ValidateAllTimers(units map[string]*types.UnitFile) map[string]TimerValidation {
	results := make(map[string]TimerValidation)

	for name, unit := range units {
		if unit.Type == "timer" {
			results[name] = ValidateTimer(unit, units)
		}
	}

	return results
}
