package validation

import (
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// PathValidation contains results of path unit validation.
type PathValidation struct {
	Unit            string
	MissingService  bool     // No matching .service
	ServiceName     string   // The expected service name
	NoPathDirective bool     // No PathExists=/PathChanged= etc.
	InvalidPaths    []string // Paths that look wrong
	WatchedPaths    []string // Paths being watched
	Issues          []string
	Valid           bool
}

// ValidatePath checks path unit configuration.
func ValidatePath(unit *types.UnitFile, allUnits map[string]*types.UnitFile) PathValidation {
	result := PathValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	if unit.Type != "path" {
		return result
	}

	pathSection, hasPath := unit.Sections["Path"]
	if !hasPath {
		result.Valid = false
		result.Issues = append(result.Issues, "Path unit has no [Path] section")
		return result
	}

	// Determine expected service name
	serviceName := getPathServiceName(unit, pathSection)
	result.ServiceName = serviceName

	// Check if service exists
	if _, exists := allUnits[serviceName]; !exists {
		result.MissingService = true
		result.Valid = false
	}

	// Check for path directives
	pathDirectives := []string{
		"PathExists",
		"PathExistsGlob",
		"PathChanged",
		"PathModified",
		"DirectoryNotEmpty",
	}

	hasPathDir := false
	for _, directive := range pathDirectives {
		if dirs, ok := pathSection.Directives[directive]; ok && len(dirs) > 0 {
			hasPathDir = true
			for _, d := range dirs {
				result.WatchedPaths = append(result.WatchedPaths, d.Value)
				if invalid := validateWatchedPath(directive, d.Value); invalid != "" {
					result.InvalidPaths = append(result.InvalidPaths, invalid)
				}
			}
		}
	}

	if !hasPathDir {
		result.NoPathDirective = true
		result.Valid = false
		result.Issues = append(result.Issues,
			"Path unit has no path directives (PathExists, PathChanged, etc.)")
	}

	if len(result.InvalidPaths) > 0 || len(result.Issues) > 0 {
		result.Valid = false
	}

	return result
}

// getPathServiceName determines which service this path unit activates.
func getPathServiceName(unit *types.UnitFile, pathSection *types.Section) string {
	// Check explicit Unit= directive
	if service := getDirectiveValue(pathSection, "Unit"); service != "" {
		return service
	}

	// Default: same name with .service extension
	return strings.TrimSuffix(unit.Name, ".path") + ".service"
}

// validateWatchedPath checks if a watched path looks valid.
func validateWatchedPath(directive, value string) string {
	if value == "" {
		return "Empty path for " + directive
	}

	// PathExistsGlob can have glob patterns
	if directive == "PathExistsGlob" {
		// Globs are valid
		return ""
	}

	// Other directives should be absolute paths
	if !strings.HasPrefix(value, "/") {
		return value + " is not an absolute path"
	}

	// Check for obviously problematic paths
	if value == "/" {
		return "Watching root directory (/) is likely unintended"
	}

	if strings.HasPrefix(value, "/proc") || strings.HasPrefix(value, "/sys") {
		// These are generally okay for path watching
		return ""
	}

	// Check for paths that might cause issues
	if strings.Contains(value, "..") {
		return value + " contains parent directory reference (..)"
	}

	return ""
}

// ValidateAllPaths validates all path units in a collection.
func ValidateAllPaths(units map[string]*types.UnitFile) map[string]PathValidation {
	results := make(map[string]PathValidation)

	for name, unit := range units {
		if unit.Type == "path" {
			results[name] = ValidatePath(unit, units)
		}
	}

	return results
}

// TargetValidation contains results of target unit validation.
type TargetValidation struct {
	Unit            string
	Conflicts       []string // Units that conflict with this target
	RequiredBy      []string // Units that require this target
	WantedBy        []string // Units that want this target
	PullsIn         []string // Units this target pulls in
	IsDefaultTarget bool
	Issues          []string
	Valid           bool
}

// ValidateTarget performs minimal validation on target units.
// Targets are generally very permissive.
func ValidateTarget(unit *types.UnitFile, allUnits map[string]*types.UnitFile) TargetValidation {
	result := TargetValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	if unit.Type != "target" {
		return result
	}

	// Check Unit section
	if unitSection, ok := unit.Sections["Unit"]; ok {
		// Collect conflicts
		if dirs, ok := unitSection.Directives["Conflicts"]; ok {
			for _, d := range dirs {
				result.Conflicts = append(result.Conflicts, strings.Fields(d.Value)...)
			}
		}

		// Collect requirements
		for _, directive := range []string{"Requires", "Wants"} {
			if dirs, ok := unitSection.Directives[directive]; ok {
				for _, d := range dirs {
					result.PullsIn = append(result.PullsIn, strings.Fields(d.Value)...)
				}
			}
		}
	}

	// Check Install section for reverse dependencies
	if installSection, ok := unit.Sections["Install"]; ok {
		if dirs, ok := installSection.Directives["RequiredBy"]; ok {
			for _, d := range dirs {
				result.RequiredBy = append(result.RequiredBy, strings.Fields(d.Value)...)
			}
		}
		if dirs, ok := installSection.Directives["WantedBy"]; ok {
			for _, d := range dirs {
				result.WantedBy = append(result.WantedBy, strings.Fields(d.Value)...)
			}
		}
	}

	// Check if this is the default target
	if unit.Name == "default.target" {
		result.IsDefaultTarget = true
	}

	// Look for conflicting configuration
	for _, conflict := range result.Conflicts {
		for _, pullsIn := range result.PullsIn {
			if conflict == pullsIn {
				result.Issues = append(result.Issues,
					"Target both Conflicts with and Requires/Wants "+conflict)
				result.Valid = false
			}
		}
	}

	return result
}
