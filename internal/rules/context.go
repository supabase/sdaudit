package rules

import (
	"github.com/samrose/sdaudit/pkg/types"
)

// Context provides the execution context for rules
type Context struct {
	Unit       *types.UnitFile
	AllUnits   map[string]*types.UnitFile
	SystemInfo *SystemInfo
	Config     *Config
}

// SystemInfo contains information about the target system
type SystemInfo struct {
	Hostname       string
	SystemdVersion string
	OSRelease      string
	IsRunning      bool
}

// Config contains configuration for rule execution
type Config struct {
	DisabledRules     map[string]bool
	SeverityOverrides map[string]types.Severity
	Thresholds        Thresholds
}

// Thresholds contains configurable threshold values for rules
type Thresholds struct {
	SecurityScoreMax     float64
	BootCriticalChainMax float64
	RestartSecMin        float64
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		DisabledRules:     make(map[string]bool),
		SeverityOverrides: make(map[string]types.Severity),
		Thresholds: Thresholds{
			SecurityScoreMax:     5.0,
			BootCriticalChainMax: 30.0,
			RestartSecMin:        1.0,
		},
	}
}

// NewContext creates a new Context for checking a single unit
func NewContext(unit *types.UnitFile) *Context {
	return &Context{
		Unit:     unit,
		AllUnits: make(map[string]*types.UnitFile),
		Config:   DefaultConfig(),
	}
}

// NewContextWithUnits creates a new Context with all units loaded
func NewContextWithUnits(unit *types.UnitFile, allUnits map[string]*types.UnitFile) *Context {
	return &Context{
		Unit:     unit,
		AllUnits: allUnits,
		Config:   DefaultConfig(),
	}
}

// IsRuleDisabled checks if a rule is disabled
func (c *Context) IsRuleDisabled(ruleID string) bool {
	if c.Config == nil {
		return false
	}
	return c.Config.DisabledRules[ruleID]
}

// GetSeverityOverride returns the overridden severity for a rule, if any
func (c *Context) GetSeverityOverride(ruleID string) (types.Severity, bool) {
	if c.Config == nil {
		return types.SeverityInfo, false
	}
	severity, ok := c.Config.SeverityOverrides[ruleID]
	return severity, ok
}
