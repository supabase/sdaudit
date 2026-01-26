package validation

import (
	"regexp"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// DirectiveValidation contains results of common directive validation.
type DirectiveValidation struct {
	Unit               string
	MissingExecutables []MissingExec // ExecStart, ExecStop, etc. not found
	NotExecutable      []MissingExec // Paths not executable
	MissingEnvFiles    []MissingFile // EnvironmentFile= not found
	MissingWorkDir     string        // WorkingDirectory= not found
	InvalidDirectories []string      // RuntimeDirectory= invalid names
	Issues             []string
	Valid              bool
}

// MissingFile represents a missing file reference.
type MissingFile struct {
	Directive string
	Path      string
	Optional  bool // Prefixed with - ?
	Line      int
}

// ValidateDirectives checks common directives across all unit types.
func ValidateDirectives(unit *types.UnitFile, fs FileSystem) DirectiveValidation {
	result := DirectiveValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	// Validate service-specific exec directives
	if serviceSection, ok := unit.Sections["Service"]; ok {
		execDirectives := []string{
			"ExecStart", "ExecStartPre", "ExecStartPost",
			"ExecStop", "ExecStopPost", "ExecReload",
			"ExecCondition",
		}

		for _, directive := range execDirectives {
			if dirs, ok := serviceSection.Directives[directive]; ok {
				for _, d := range dirs {
					missing, notExec := validateExecPath(d.Value, directive, d.Line, fs)
					result.MissingExecutables = append(result.MissingExecutables, missing...)
					result.NotExecutable = append(result.NotExecutable, notExec...)
				}
			}
		}

		// Validate EnvironmentFile=
		if dirs, ok := serviceSection.Directives["EnvironmentFile"]; ok {
			for _, d := range dirs {
				if missing := validateEnvironmentFile(d.Value, d.Line, fs); missing != nil {
					result.MissingEnvFiles = append(result.MissingEnvFiles, *missing)
				}
			}
		}

		// Validate WorkingDirectory=
		if workDir := getDirectiveValue(serviceSection, "WorkingDirectory"); workDir != "" {
			if !validateWorkingDirectory(workDir, fs) {
				result.MissingWorkDir = workDir
				result.Valid = false
			}
		}

		// Validate *Directory= directives
		dirDirectives := []string{
			"RuntimeDirectory",
			"StateDirectory",
			"CacheDirectory",
			"LogsDirectory",
			"ConfigurationDirectory",
		}

		for _, directive := range dirDirectives {
			if dirs, ok := serviceSection.Directives[directive]; ok {
				for _, d := range dirs {
					if invalid := validateDirectoryNames(d.Value); len(invalid) > 0 {
						result.InvalidDirectories = append(result.InvalidDirectories, invalid...)
					}
				}
			}
		}
	}

	// Also check socket sections for exec directives
	if socketSection, ok := unit.Sections["Socket"]; ok {
		execDirectives := []string{
			"ExecStartPre", "ExecStartPost",
			"ExecStopPre", "ExecStopPost",
		}

		for _, directive := range execDirectives {
			if dirs, ok := socketSection.Directives[directive]; ok {
				for _, d := range dirs {
					missing, notExec := validateExecPath(d.Value, directive, d.Line, fs)
					result.MissingExecutables = append(result.MissingExecutables, missing...)
					result.NotExecutable = append(result.NotExecutable, notExec...)
				}
			}
		}
	}

	// Filter out optional files from validation failures
	var requiredMissing []MissingExec
	for _, m := range result.MissingExecutables {
		if !m.Optional {
			requiredMissing = append(requiredMissing, m)
		}
	}

	var requiredEnvMissing []MissingFile
	for _, m := range result.MissingEnvFiles {
		if !m.Optional {
			requiredEnvMissing = append(requiredEnvMissing, m)
		}
	}

	if len(requiredMissing) > 0 || len(requiredEnvMissing) > 0 ||
		result.MissingWorkDir != "" || len(result.InvalidDirectories) > 0 {
		result.Valid = false
	}

	return result
}

// validateEnvironmentFile validates an EnvironmentFile= directive.
func validateEnvironmentFile(value string, line int, fs FileSystem) *MissingFile {
	if value == "" {
		return nil
	}

	optional := false
	path := value

	// - prefix means optional
	if strings.HasPrefix(path, "-") {
		optional = true
		path = path[1:]
	}

	// Skip paths with specifiers
	if strings.Contains(path, "%") {
		return nil
	}

	// Check if file exists
	if !fs.Exists(path) {
		return &MissingFile{
			Directive: "EnvironmentFile",
			Path:      path,
			Optional:  optional,
			Line:      line,
		}
	}

	return nil
}

// validateWorkingDirectory validates a WorkingDirectory= directive.
func validateWorkingDirectory(value string, fs FileSystem) bool {
	// Special values
	if value == "~" || value == "-" {
		return true
	}

	// - prefix means don't fail if missing
	if strings.HasPrefix(value, "-") {
		return true
	}

	// Skip paths with specifiers
	if strings.Contains(value, "%") {
		return true
	}

	return fs.IsDirectory(value)
}

// validateDirectoryNames validates RuntimeDirectory= etc. names.
// These are relative directory names, not paths.
func validateDirectoryNames(value string) []string {
	var invalid []string

	names := strings.Fields(value)
	for _, name := range names {
		// Remove mode suffix like :0755
		if idx := strings.Index(name, ":"); idx > 0 {
			name = name[:idx]
		}

		// Names must not be absolute paths
		if strings.HasPrefix(name, "/") {
			invalid = append(invalid, name+" (must not be absolute path)")
			continue
		}

		// Names must not contain ..
		if strings.Contains(name, "..") {
			invalid = append(invalid, name+" (must not contain ..)")
			continue
		}

		// Names should be valid directory names
		validNameRegex := regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
		if !validNameRegex.MatchString(name) && !strings.Contains(name, "/") {
			// Allow subdirectories like "myapp/cache"
			parts := strings.Split(name, "/")
			for _, part := range parts {
				if part != "" && !validNameRegex.MatchString(part) {
					invalid = append(invalid, name+" (invalid characters)")
					break
				}
			}
		}
	}

	return invalid
}

// ValidateAllDirectives validates common directives for all units.
func ValidateAllDirectives(units map[string]*types.UnitFile, fs FileSystem) map[string]DirectiveValidation {
	results := make(map[string]DirectiveValidation)

	for name, unit := range units {
		results[name] = ValidateDirectives(unit, fs)
	}

	return results
}

// DeprecatedDirective represents a deprecated directive usage.
type DeprecatedDirective struct {
	Unit        string
	Directive   string
	Replacement string
	Line        int
}

// DeprecatedDirectives maps deprecated directives to their replacements.
var DeprecatedDirectives = map[string]string{
	"StartLimitInterval":            "StartLimitIntervalSec (in [Unit] section)",
	"StartLimitBurst":               "StartLimitBurst (now preferred in [Unit] section)",
	"BlockIOWeight":                 "IOWeight (cgroup v2)",
	"BlockIODeviceWeight":           "IODeviceWeight (cgroup v2)",
	"BlockIOReadBandwidth":          "IOReadBandwidthMax (cgroup v2)",
	"BlockIOWriteBandwidth":         "IOWriteBandwidthMax (cgroup v2)",
	"MemoryLimit":                   "MemoryMax (cgroup v2)",
	"CPUShares":                     "CPUWeight (cgroup v2)",
	"StartupCPUShares":              "StartupCPUWeight (cgroup v2)",
	"CPUQuota":                      "CPUQuota (still valid, but consider CPUWeight)",
	"Alias":                         "symlinks via systemctl enable",
	"StandardOutput=syslog":         "StandardOutput=journal",
	"StandardError=syslog":          "StandardError=journal",
	"StandardOutput=syslog+console": "StandardOutput=journal+console",
	"StandardError=syslog+console":  "StandardError=journal+console",
}

// FindDeprecatedDirectives finds deprecated directive usage in units.
func FindDeprecatedDirectives(units map[string]*types.UnitFile) []DeprecatedDirective {
	var deprecated []DeprecatedDirective

	for unitName, unit := range units {
		for _, section := range unit.Sections {
			for directive, dirs := range section.Directives {
				if replacement, isDeprecated := DeprecatedDirectives[directive]; isDeprecated {
					for _, d := range dirs {
						deprecated = append(deprecated, DeprecatedDirective{
							Unit:        unitName,
							Directive:   directive,
							Replacement: replacement,
							Line:        d.Line,
						})
					}
				}

				// Check for deprecated values
				for _, d := range dirs {
					if directive == "StandardOutput" || directive == "StandardError" {
						key := directive + "=" + d.Value
						if replacement, isDeprecated := DeprecatedDirectives[key]; isDeprecated {
							deprecated = append(deprecated, DeprecatedDirective{
								Unit:        unitName,
								Directive:   key,
								Replacement: replacement,
								Line:        d.Line,
							})
						}
					}
				}
			}
		}
	}

	return deprecated
}
