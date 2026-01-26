package validation

import (
	"fmt"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// ServiceValidation contains results of service unit validation.
type ServiceValidation struct {
	Unit                 string
	ExecStartMissing     bool            // No ExecStart= defined
	ExecStartNotFound    []MissingExec   // Paths that don't exist
	ExecStartNotExec     []MissingExec   // Paths not executable
	UserNotFound         string          // User= doesn't exist
	GroupNotFound        string          // Group= doesn't exist
	ContradictorySandbox []Contradiction // e.g., PrivateNetwork + curl
	TypeIssues           []string        // Issues with Type= setting
	Valid                bool
}

// MissingExec represents a missing or non-executable path.
type MissingExec struct {
	Directive string // "ExecStart", "ExecStop", etc.
	Path      string // The path that's missing
	Optional  bool   // Prefixed with - ?
	Line      int
}

// Contradiction represents contradictory sandboxing settings.
type Contradiction struct {
	Setting       string // "PrivateNetwork=yes"
	ConflictsWith string // "ExecStart uses curl"
	Severity      string
	Description   string
}

// ValidateService performs service-specific checks.
func ValidateService(unit *types.UnitFile, fs FileSystem) ServiceValidation {
	result := ServiceValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	if unit.Type != "service" {
		return result
	}

	serviceSection, hasService := unit.Sections["Service"]
	if !hasService {
		result.Valid = false
		return result
	}

	// Check for ExecStart=
	execStartDirs := serviceSection.Directives["ExecStart"]
	serviceType := getDirectiveValue(serviceSection, "Type")

	// Type=oneshot can have empty ExecStart if it has ExecStop
	if len(execStartDirs) == 0 && serviceType != "oneshot" {
		result.ExecStartMissing = true
		result.Valid = false
	}

	// Validate all Exec* directives
	execDirectives := []string{
		"ExecStart", "ExecStartPre", "ExecStartPost",
		"ExecStop", "ExecStopPost", "ExecReload",
	}

	for _, directive := range execDirectives {
		if dirs, ok := serviceSection.Directives[directive]; ok {
			for _, d := range dirs {
				missing, notExec := validateExecPath(d.Value, directive, d.Line, fs)
				result.ExecStartNotFound = append(result.ExecStartNotFound, missing...)
				result.ExecStartNotExec = append(result.ExecStartNotExec, notExec...)
			}
		}
	}

	// Check User= and Group=
	if userVal := getDirectiveValue(serviceSection, "User"); userVal != "" {
		if !fs.UserExists(userVal) {
			result.UserNotFound = userVal
			result.Valid = false
		}
	}

	if groupVal := getDirectiveValue(serviceSection, "Group"); groupVal != "" {
		if !fs.GroupExists(groupVal) {
			result.GroupNotFound = groupVal
			result.Valid = false
		}
	}

	// Check for contradictory sandboxing
	result.ContradictorySandbox = checkContradictorySandboxing(unit, serviceSection)

	// Check Type= specific issues
	result.TypeIssues = validateServiceType(serviceSection, unit)

	if len(result.ExecStartNotFound) > 0 || len(result.ContradictorySandbox) > 0 || len(result.TypeIssues) > 0 {
		result.Valid = false
	}

	return result
}

// validateExecPath validates an Exec* directive value.
func validateExecPath(value, directive string, line int, fs FileSystem) (missing []MissingExec, notExec []MissingExec) {
	// Handle empty value (reset directive)
	if value == "" {
		return
	}

	// Parse the command line
	// Format: [-][@][!][|][+][:]<path> [arguments...]
	// - = failure is OK
	// @ = don't do automatic argument handling
	// ! = don't apply ambient capabilities
	// | = don't prefix command with sd_notify
	// + = run with full privileges
	// : = passed to sd_exec directly

	cmd := value
	optional := false

	// Strip prefixes
	for len(cmd) > 0 {
		switch cmd[0] {
		case '-':
			optional = true
			cmd = cmd[1:]
		case '@', '!', '|', '+', ':':
			cmd = cmd[1:]
		default:
			goto parsePath
		}
	}

parsePath:
	// Get the executable path (first word)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}

	execPath := parts[0]

	// Handle special cases
	if execPath == "" {
		return
	}

	// Skip systemd specifiers like %t, %S, etc.
	if strings.Contains(execPath, "%") {
		return // Can't validate paths with specifiers
	}

	// Check if path exists
	if !fs.Exists(execPath) {
		missing = append(missing, MissingExec{
			Directive: directive,
			Path:      execPath,
			Optional:  optional,
			Line:      line,
		})
		return
	}

	// Check if executable
	if !fs.IsExecutable(execPath) {
		notExec = append(notExec, MissingExec{
			Directive: directive,
			Path:      execPath,
			Optional:  optional,
			Line:      line,
		})
	}

	return
}

// checkContradictorySandboxing detects contradictory sandboxing settings.
func checkContradictorySandboxing(unit *types.UnitFile, serviceSection *types.Section) []Contradiction {
	var contradictions []Contradiction

	// Get sandboxing settings
	privateNetwork := getDirectiveValue(serviceSection, "PrivateNetwork") == "yes" ||
		getDirectiveValue(serviceSection, "PrivateNetwork") == "true"
	privateUsers := getDirectiveValue(serviceSection, "PrivateUsers") == "yes" ||
		getDirectiveValue(serviceSection, "PrivateUsers") == "true"
	protectSystem := getDirectiveValue(serviceSection, "ProtectSystem")
	readOnlyPaths := serviceSection.Directives["ReadOnlyPaths"]
	inaccessiblePaths := serviceSection.Directives["InaccessiblePaths"]

	// Get exec commands to check for contradictions
	var execPaths []string
	for _, directive := range []string{"ExecStart", "ExecStartPre", "ExecReload"} {
		if dirs, ok := serviceSection.Directives[directive]; ok {
			for _, d := range dirs {
				execPaths = append(execPaths, d.Value)
			}
		}
	}

	// Check PrivateNetwork with network-dependent commands
	if privateNetwork {
		networkBinaries := []string{"curl", "wget", "ping", "ssh", "nc", "netcat", "socat"}
		for _, exec := range execPaths {
			for _, bin := range networkBinaries {
				if strings.Contains(exec, "/"+bin) || strings.HasPrefix(exec, bin+" ") {
					contradictions = append(contradictions, Contradiction{
						Setting:       "PrivateNetwork=yes",
						ConflictsWith: fmt.Sprintf("ExecStart uses %s", bin),
						Severity:      "high",
						Description:   fmt.Sprintf("PrivateNetwork=yes but ExecStart uses %s which requires network access", bin),
					})
				}
			}
		}
	}

	// Check PrivateUsers with User= that might need real UID
	if privateUsers {
		user := getDirectiveValue(serviceSection, "User")
		if user != "" && user != "root" && user != "nobody" {
			// Check if user is numeric (UID) vs name
			if _, isNumeric := isNumericUser(user); !isNumeric {
				contradictions = append(contradictions, Contradiction{
					Setting:       "PrivateUsers=yes",
					ConflictsWith: fmt.Sprintf("User=%s", user),
					Severity:      "medium",
					Description:   "PrivateUsers=yes may cause User= lookup to fail if user doesn't exist in private namespace",
				})
			}
		}
	}

	// Check ProtectSystem with write operations
	if protectSystem == "strict" || protectSystem == "full" {
		// Check if any ExecStart writes to protected areas
		for _, exec := range execPaths {
			if strings.Contains(exec, ">/") || strings.Contains(exec, ">> /") {
				// Very basic check for redirects to absolute paths
				contradictions = append(contradictions, Contradiction{
					Setting:       fmt.Sprintf("ProtectSystem=%s", protectSystem),
					ConflictsWith: "Command appears to write to filesystem",
					Severity:      "medium",
					Description:   "ProtectSystem may prevent write operations in ExecStart",
				})
			}
		}
	}

	// Check ReadOnlyPaths/InaccessiblePaths with WorkingDirectory
	workDir := getDirectiveValue(serviceSection, "WorkingDirectory")
	if workDir != "" {
		for _, d := range readOnlyPaths {
			if strings.HasPrefix(workDir, d.Value) {
				contradictions = append(contradictions, Contradiction{
					Setting:       fmt.Sprintf("ReadOnlyPaths=%s", d.Value),
					ConflictsWith: fmt.Sprintf("WorkingDirectory=%s", workDir),
					Severity:      "medium",
					Description:   "WorkingDirectory is under a ReadOnlyPaths path",
				})
			}
		}
		for _, d := range inaccessiblePaths {
			if strings.HasPrefix(workDir, d.Value) {
				contradictions = append(contradictions, Contradiction{
					Setting:       fmt.Sprintf("InaccessiblePaths=%s", d.Value),
					ConflictsWith: fmt.Sprintf("WorkingDirectory=%s", workDir),
					Severity:      "high",
					Description:   "WorkingDirectory is under an InaccessiblePaths path",
				})
			}
		}
	}

	return contradictions
}

func isNumericUser(user string) (int, bool) {
	var uid int
	_, err := fmt.Sscanf(user, "%d", &uid)
	return uid, err == nil
}

// validateServiceType checks for issues with the Type= setting.
func validateServiceType(serviceSection *types.Section, unit *types.UnitFile) []string {
	var issues []string

	serviceType := getDirectiveValue(serviceSection, "Type")
	if serviceType == "" {
		serviceType = "simple" // Default
	}

	execStart := serviceSection.Directives["ExecStart"]
	busName := getDirectiveValue(serviceSection, "BusName")
	pidFile := getDirectiveValue(serviceSection, "PIDFile")

	switch serviceType {
	case "simple":
		// Simple services should have ExecStart
		if len(execStart) == 0 {
			issues = append(issues, "Type=simple but no ExecStart= defined")
		}

	case "exec":
		// Same as simple but waits for exec()
		if len(execStart) == 0 {
			issues = append(issues, "Type=exec but no ExecStart= defined")
		}

	case "forking":
		// Forking services should have PIDFile
		if pidFile == "" {
			issues = append(issues, "Type=forking without PIDFile= may cause systemd to lose track of the process")
		}

	case "oneshot":
		// Oneshot services typically should have RemainAfterExit
		// but it's not always an issue, just informational
		_ = getDirectiveValue(serviceSection, "RemainAfterExit")

	case "dbus":
		// D-Bus services must have BusName
		if busName == "" {
			issues = append(issues, "Type=dbus requires BusName= to be set")
		}

	case "notify":
		// Notify services should use sd_notify
		// Default NotifyAccess is "main", which is usually fine

	case "idle":
		// Idle services wait until no jobs are pending
		// No specific requirements

	default:
		issues = append(issues, fmt.Sprintf("Unknown Type=%s", serviceType))
	}

	return issues
}

// getDirectiveValue gets the first value of a directive.
func getDirectiveValue(section *types.Section, key string) string {
	if section == nil {
		return ""
	}
	if dirs, ok := section.Directives[key]; ok && len(dirs) > 0 {
		return dirs[0].Value
	}
	return ""
}
