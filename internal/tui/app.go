package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/samrose/sdaudit/internal/analyzer"
	"github.com/samrose/sdaudit/pkg/types"
)

// View represents the current view in the TUI
type View int

const (
	ViewDashboard View = iota
	ViewIssues
	ViewUnitDetail
	ViewHelp
)

// Model is the main application model
type Model struct {
	result    *analyzer.ScanResult
	styles    Styles
	view      View
	width     int
	height    int
	issueList list.Model
	quitting  bool
}

// IssueItem represents an issue in the list
type IssueItem struct {
	issue types.Issue
}

func (i IssueItem) Title() string {
	return fmt.Sprintf("[%s] %s", i.issue.RuleID, i.issue.RuleName)
}

func (i IssueItem) Description() string {
	return fmt.Sprintf("%s - %s", i.issue.Unit, i.issue.Description)
}

func (i IssueItem) FilterValue() string {
	return i.issue.Unit + " " + i.issue.RuleID + " " + i.issue.RuleName
}

// KeyMap defines the key bindings
type KeyMap struct {
	Up        key.Binding
	Down      key.Binding
	Enter     key.Binding
	Back      key.Binding
	Dashboard key.Binding
	Issues    key.Binding
	Filter    key.Binding
	Rescan    key.Binding
	Help      key.Binding
	Quit      key.Binding
}

var keys = KeyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	),
	Dashboard: key.NewBinding(
		key.WithKeys("d"),
		key.WithHelp("d", "dashboard"),
	),
	Issues: key.NewBinding(
		key.WithKeys("i"),
		key.WithHelp("i", "issues"),
	),
	Filter: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "filter"),
	),
	Rescan: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "rescan"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
}

// New creates a new TUI model with the given scan result
func New(result *analyzer.ScanResult) Model {
	styles := DefaultStyles()

	// Create issue list
	items := make([]list.Item, len(result.Issues))
	for i, issue := range result.Issues {
		items[i] = IssueItem{issue: issue}
	}

	delegate := list.NewDefaultDelegate()
	issueList := list.New(items, delegate, 0, 0)
	issueList.Title = "Issues"
	issueList.SetShowStatusBar(true)
	issueList.SetFilteringEnabled(true)

	return Model{
		result:    result,
		styles:    styles,
		view:      ViewDashboard,
		issueList: issueList,
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.issueList.SetSize(msg.Width-4, msg.Height-8)
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			m.quitting = true
			return m, tea.Quit

		case key.Matches(msg, keys.Back):
			if m.view != ViewDashboard {
				m.view = ViewDashboard
			}
			return m, nil

		case key.Matches(msg, keys.Dashboard):
			m.view = ViewDashboard
			return m, nil

		case key.Matches(msg, keys.Issues):
			m.view = ViewIssues
			return m, nil

		case key.Matches(msg, keys.Help):
			if m.view == ViewHelp {
				m.view = ViewDashboard
			} else {
				m.view = ViewHelp
			}
			return m, nil

		case key.Matches(msg, keys.Enter):
			if m.view == ViewIssues {
				m.view = ViewUnitDetail
			}
			return m, nil
		}
	}

	// Update the list if we're in issues view
	if m.view == ViewIssues {
		var cmd tea.Cmd
		m.issueList, cmd = m.issueList.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View implements tea.Model
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var content string
	switch m.view {
	case ViewDashboard:
		content = m.viewDashboard()
	case ViewIssues:
		content = m.viewIssues()
	case ViewUnitDetail:
		content = m.viewUnitDetail()
	case ViewHelp:
		content = m.viewHelp()
	}

	return m.styles.App.Render(content)
}

func (m Model) viewDashboard() string {
	var b strings.Builder

	// Header
	header := m.styles.Header.Render(" sdaudit - Systemd Auditing Tool ")
	b.WriteString(header + "\n\n")

	// Summary
	summary := m.result.Summary
	b.WriteString(m.styles.Title.Render("Scan Summary") + "\n")
	b.WriteString(fmt.Sprintf("  Units scanned: %d\n", summary.TotalUnits))
	b.WriteString(fmt.Sprintf("  Rules checked: %d\n", summary.RulesChecked))
	b.WriteString(fmt.Sprintf("  Issues found:  %d\n\n", summary.TotalIssues))

	// Severity breakdown with bars
	b.WriteString(m.styles.Title.Render("Issues by Severity") + "\n")
	maxWidth := 40
	maxCount := 0
	for _, count := range summary.BySeverity {
		if count > maxCount {
			maxCount = count
		}
	}
	if maxCount == 0 {
		maxCount = 1
	}

	severities := []types.Severity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	for _, sev := range severities {
		count := summary.BySeverity[sev]
		barWidth := (count * maxWidth) / maxCount
		if count > 0 && barWidth == 0 {
			barWidth = 1
		}

		sevStyle := m.styles.SeverityStyle(sev.String())
		label := sevStyle.Render(fmt.Sprintf("  %-10s", strings.ToUpper(sev.String())))
		countStr := fmt.Sprintf("%3d ", count)
		bar := RenderBar(barWidth, barWidth, sevStyle)
		b.WriteString(label + countStr + bar + "\n")
	}
	b.WriteString("\n")

	// Category breakdown
	b.WriteString(m.styles.Title.Render("Issues by Category") + "\n")
	categories := []types.Category{
		types.CategorySecurity,
		types.CategoryReliability,
		types.CategoryPerformance,
		types.CategoryBestPractice,
	}
	for _, cat := range categories {
		count := summary.ByCategory[cat]
		b.WriteString(fmt.Sprintf("  %-15s %d\n", cat.String(), count))
	}

	// Help bar
	b.WriteString("\n" + m.styles.HelpBar.Render("[i]ssues  [d]ashboard  [r]escan  [?]help  [q]uit"))

	return b.String()
}

func (m Model) viewIssues() string {
	return m.issueList.View()
}

func (m Model) viewUnitDetail() string {
	var b strings.Builder

	// Get selected issue
	selectedItem := m.issueList.SelectedItem()
	if selectedItem == nil {
		b.WriteString("No issue selected\n")
		b.WriteString("\n" + m.styles.HelpBar.Render("[esc] back"))
		return b.String()
	}

	item := selectedItem.(IssueItem)
	issue := item.issue

	// Header
	b.WriteString(m.styles.Title.Render("Issue Detail") + "\n\n")

	// Issue info
	sevStyle := m.styles.SeverityStyle(issue.Severity.String())
	b.WriteString(fmt.Sprintf("Rule:     %s\n", m.styles.Bold.Render(issue.RuleID)))
	b.WriteString(fmt.Sprintf("Name:     %s\n", issue.RuleName))
	b.WriteString(fmt.Sprintf("Severity: %s\n", sevStyle.Render(strings.ToUpper(issue.Severity.String()))))
	b.WriteString(fmt.Sprintf("Category: %s\n", issue.Category.String()))
	b.WriteString(fmt.Sprintf("Unit:     %s\n", m.styles.Bold.Render(issue.Unit)))
	b.WriteString(fmt.Sprintf("File:     %s\n", issue.File))
	if issue.Line != nil {
		b.WriteString(fmt.Sprintf("Line:     %d\n", *issue.Line))
	}
	b.WriteString("\n")

	// Description
	b.WriteString(m.styles.Title.Render("Description") + "\n")
	b.WriteString("  " + issue.Description + "\n\n")

	// Suggestion
	b.WriteString(m.styles.Title.Render("Suggestion") + "\n")
	b.WriteString("  " + issue.Suggestion + "\n\n")

	// References
	if len(issue.References) > 0 {
		b.WriteString(m.styles.Title.Render("References") + "\n")
		for _, ref := range issue.References {
			b.WriteString("  " + m.styles.Muted.Render(ref) + "\n")
		}
	}

	// Tags
	if len(issue.Tags) > 0 {
		b.WriteString("\n" + m.styles.Title.Render("Tags") + "\n")
		b.WriteString("  " + strings.Join(issue.Tags, ", ") + "\n")
	}

	b.WriteString("\n" + m.styles.HelpBar.Render("[esc] back  [q]uit"))

	return b.String()
}

func (m Model) viewHelp() string {
	var b strings.Builder

	b.WriteString(m.styles.Title.Render("Keyboard Shortcuts") + "\n\n")

	helpItems := []struct {
		key  string
		desc string
	}{
		{"↑/k, ↓/j", "Navigate up/down"},
		{"Enter", "Select/expand"},
		{"Esc", "Go back"},
		{"d", "Dashboard view"},
		{"i", "Issues list"},
		{"/", "Filter/search"},
		{"r", "Rescan"},
		{"?", "Toggle help"},
		{"q", "Quit"},
	}

	for _, item := range helpItems {
		b.WriteString(fmt.Sprintf("  %-12s  %s\n", m.styles.Bold.Render(item.key), item.desc))
	}

	b.WriteString("\n" + m.styles.HelpBar.Render("[esc] back  [q]uit"))

	return b.String()
}

// Run starts the TUI application
func Run(result *analyzer.ScanResult) error {
	p := tea.NewProgram(New(result), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
