package types

// Severity represents the severity level of an issue
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string to a Severity level
func ParseSeverity(s string) Severity {
	switch s {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// Category represents the category of a rule
type Category int

const (
	CategorySecurity Category = iota
	CategoryPerformance
	CategoryReliability
	CategoryBestPractice
)

func (c Category) String() string {
	switch c {
	case CategorySecurity:
		return "security"
	case CategoryPerformance:
		return "performance"
	case CategoryReliability:
		return "reliability"
	case CategoryBestPractice:
		return "bestpractice"
	default:
		return "unknown"
	}
}

// ParseCategory converts a string to a Category
func ParseCategory(s string) Category {
	switch s {
	case "security":
		return CategorySecurity
	case "performance":
		return CategoryPerformance
	case "reliability":
		return CategoryReliability
	case "bestpractice":
		return CategoryBestPractice
	default:
		return CategorySecurity
	}
}

// Issue represents a detected issue in a systemd unit
type Issue struct {
	RuleID      string   `json:"id"`
	RuleName    string   `json:"name"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Tags        []string `json:"tags"`
	Unit        string   `json:"unit"`
	File        string   `json:"file"`
	Line        *int     `json:"line,omitempty"`
	Description string   `json:"description"`
	Suggestion  string   `json:"suggestion"`
	References  []string `json:"references"`
}

// UnitFile represents a parsed systemd unit file
type UnitFile struct {
	Name     string              // e.g., "nginx.service"
	Path     string              // e.g., "/lib/systemd/system/nginx.service"
	Type     string              // e.g., "service", "socket", "timer"
	Sections map[string]*Section // e.g., "Unit", "Service", "Install"
	Raw      string              // Raw file contents
}

// Section represents a section in a unit file (e.g., [Service])
type Section struct {
	Name       string
	Directives map[string][]Directive
}

// Directive represents a single directive in a unit file
type Directive struct {
	Key   string
	Value string
	Line  int
}

// GetDirective returns the first value for a directive, or empty string if not found
func (u *UnitFile) GetDirective(section, key string) string {
	if s, ok := u.Sections[section]; ok {
		if directives, ok := s.Directives[key]; ok && len(directives) > 0 {
			return directives[0].Value
		}
	}
	return ""
}

// GetDirectives returns all values for a directive
func (u *UnitFile) GetDirectives(section, key string) []Directive {
	if s, ok := u.Sections[section]; ok {
		if directives, ok := s.Directives[key]; ok {
			return directives
		}
	}
	return nil
}

// HasDirective checks if a directive exists in a section
func (u *UnitFile) HasDirective(section, key string) bool {
	if s, ok := u.Sections[section]; ok {
		_, ok := s.Directives[key]
		return ok
	}
	return false
}

// IsService returns true if this is a service unit
func (u *UnitFile) IsService() bool {
	return u.Type == "service"
}

// IsSocket returns true if this is a socket unit
func (u *UnitFile) IsSocket() bool {
	return u.Type == "socket"
}

// IsTimer returns true if this is a timer unit
func (u *UnitFile) IsTimer() bool {
	return u.Type == "timer"
}
