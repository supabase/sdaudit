package reporter

import (
	"encoding/json"
	"io"

	"github.com/samrose/sdaudit/internal/analyzer"
	"github.com/samrose/sdaudit/internal/rules"
	"github.com/samrose/sdaudit/pkg/types"
)

// SARIFReporter outputs scan results in SARIF 2.1.0 format
type SARIFReporter struct {
	w      io.Writer
	pretty bool
}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter(w io.Writer, pretty bool) *SARIFReporter {
	return &SARIFReporter{w: w, pretty: pretty}
}

// SARIF format structures following SARIF 2.1.0 spec
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	InformationURI string                     `json:"informationUri"`
	Rules          []SARIFReportingDescriptor `json:"rules"`
}

type SARIFReportingDescriptor struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     SARIFMessage        `json:"shortDescription"`
	FullDescription      SARIFMessage        `json:"fullDescription,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	Help                 *SARIFMessage       `json:"help,omitempty"`
	Properties           map[string]any      `json:"properties,omitempty"`
	DefaultConfiguration *SARIFConfiguration `json:"defaultConfiguration,omitempty"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	Fixes     []SARIFFix      `json:"fixes,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFFix struct {
	Description SARIFMessage `json:"description"`
}

// severityToLevel converts our severity to SARIF level
func severityToLevel(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow, types.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// Report writes the scan result as SARIF
func (r *SARIFReporter) Report(result *analyzer.ScanResult) error {
	// Build rule index map and rules list
	allRules := rules.All()
	ruleIndex := make(map[string]int)
	sarifRules := make([]SARIFReportingDescriptor, len(allRules))

	for i, rule := range allRules {
		ruleIndex[rule.ID()] = i

		var helpURI string
		refs := rule.References()
		if len(refs) > 0 {
			helpURI = refs[0]
		}

		props := map[string]any{
			"tags": append([]string{rule.Category().String()}, rule.Tags()...),
		}

		sarifRules[i] = SARIFReportingDescriptor{
			ID:   rule.ID(),
			Name: rule.Name(),
			ShortDescription: SARIFMessage{
				Text: rule.Name(),
			},
			FullDescription: SARIFMessage{
				Text: rule.Description(),
			},
			HelpURI: helpURI,
			Help: &SARIFMessage{
				Text: rule.Suggestion(),
			},
			Properties: props,
			DefaultConfiguration: &SARIFConfiguration{
				Level: severityToLevel(rule.Severity()),
			},
		}
	}

	// Build results
	sarifResults := make([]SARIFResult, len(result.Issues))
	for i, issue := range result.Issues {
		idx, ok := ruleIndex[issue.RuleID]
		if !ok {
			idx = 0
		}

		sarifResult := SARIFResult{
			RuleID:    issue.RuleID,
			RuleIndex: idx,
			Level:     severityToLevel(issue.Severity),
			Message: SARIFMessage{
				Text: issue.Description,
			},
		}

		// Add location if we have file info
		if issue.File != "" {
			loc := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: issue.File,
					},
				},
			}
			if issue.Line != nil {
				loc.PhysicalLocation.Region = &SARIFRegion{
					StartLine: *issue.Line,
				}
			}
			sarifResult.Locations = []SARIFLocation{loc}
		}

		// Add fix suggestion
		if issue.Suggestion != "" {
			sarifResult.Fixes = []SARIFFix{{
				Description: SARIFMessage{
					Text: issue.Suggestion,
				},
			}}
		}

		sarifResults[i] = sarifResult
	}

	output := SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "sdaudit",
					Version:        "1.0.0",
					InformationURI: "https://github.com/samrose/sdaudit",
					Rules:          sarifRules,
				},
			},
			Results: sarifResults,
		}},
	}

	encoder := json.NewEncoder(r.w)
	if r.pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(output)
}
