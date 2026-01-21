package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// Color palette
var (
	ColorCritical = lipgloss.Color("#FF0000")
	ColorHigh     = lipgloss.Color("#FF6600")
	ColorMedium   = lipgloss.Color("#FFCC00")
	ColorLow      = lipgloss.Color("#00CCFF")
	ColorInfo     = lipgloss.Color("#888888")
	ColorOK       = lipgloss.Color("#00FF00")
	ColorMuted    = lipgloss.Color("#666666")
	ColorAccent   = lipgloss.Color("#7D56F4")
	ColorWhite    = lipgloss.Color("#FFFFFF")
)

// Styles holds all the application styles
type Styles struct {
	App              lipgloss.Style
	Header           lipgloss.Style
	Title            lipgloss.Style
	Subtitle         lipgloss.Style
	StatusBar        lipgloss.Style
	HelpBar          lipgloss.Style
	Panel            lipgloss.Style
	PanelTitle       lipgloss.Style
	List             lipgloss.Style
	ListItem         lipgloss.Style
	ListItemSelected lipgloss.Style
	SeverityCritical lipgloss.Style
	SeverityHigh     lipgloss.Style
	SeverityMedium   lipgloss.Style
	SeverityLow      lipgloss.Style
	SeverityInfo     lipgloss.Style
	Category         lipgloss.Style
	Bar              lipgloss.Style
	Muted            lipgloss.Style
	Bold             lipgloss.Style
}

// DefaultStyles returns the default style configuration
func DefaultStyles() Styles {
	return Styles{
		App: lipgloss.NewStyle().
			Padding(1, 2),

		Header: lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorWhite).
			Background(ColorAccent).
			Padding(0, 1).
			MarginBottom(1),

		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccent),

		Subtitle: lipgloss.NewStyle().
			Foreground(ColorMuted),

		StatusBar: lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1),

		HelpBar: lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1),

		Panel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorMuted).
			Padding(0, 1),

		PanelTitle: lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorAccent),

		List: lipgloss.NewStyle(),

		ListItem: lipgloss.NewStyle().
			PaddingLeft(2),

		ListItemSelected: lipgloss.NewStyle().
			PaddingLeft(2).
			Foreground(ColorWhite).
			Background(ColorAccent),

		SeverityCritical: lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCritical),

		SeverityHigh: lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorHigh),

		SeverityMedium: lipgloss.NewStyle().
			Foreground(ColorMedium),

		SeverityLow: lipgloss.NewStyle().
			Foreground(ColorLow),

		SeverityInfo: lipgloss.NewStyle().
			Foreground(ColorInfo),

		Category: lipgloss.NewStyle().
			Foreground(ColorAccent),

		Bar: lipgloss.NewStyle().
			Foreground(ColorAccent),

		Muted: lipgloss.NewStyle().
			Foreground(ColorMuted),

		Bold: lipgloss.NewStyle().
			Bold(true),
	}
}

// SeverityStyle returns the appropriate style for a severity level
func (s Styles) SeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return s.SeverityCritical
	case "high":
		return s.SeverityHigh
	case "medium":
		return s.SeverityMedium
	case "low":
		return s.SeverityLow
	default:
		return s.SeverityInfo
	}
}

// RenderBar renders a horizontal bar for visualization
func RenderBar(width int, filled int, style lipgloss.Style) string {
	if width <= 0 {
		return ""
	}
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	return style.Render(bar)
}
