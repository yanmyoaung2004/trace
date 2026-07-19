package tui

import "github.com/charmbracelet/lipgloss"

var (
	primary   = lipgloss.Color("#00BFFF")
	secondary = lipgloss.Color("#708090")
	accent    = lipgloss.Color("#FFD700")
	success   = lipgloss.Color("#32CD32")
	warning   = lipgloss.Color("#FFA500")
	danger    = lipgloss.Color("#FF4444")
	muted     = lipgloss.Color("#666666")
	bg        = lipgloss.Color("#1a1a2e")
	surface   = lipgloss.Color("#16213e")
	border    = lipgloss.Color("#0f3460")
	text      = lipgloss.Color("#e0e0e0")
	textDim   = lipgloss.Color("#888888")

	DocStyle = lipgloss.NewStyle().
		Padding(1, 2)

	TitleStyle = lipgloss.NewStyle().
		Foreground(primary).
		Bold(true).
		MarginBottom(1)

	StatusBarStyle = lipgloss.NewStyle().
		Foreground(textDim).
		Background(surface).
		Padding(0, 1)

	TabStyle = lipgloss.NewStyle().
		Padding(0, 2).
		Foreground(textDim)

	ActiveTabStyle = TabStyle.Copy().
		Foreground(primary).
		Bold(true).
		Border(lipgloss.Border{
			Top:    "─",
			Right:  "│",
			Bottom: " ",
			Left:   "│",
		}, false, true, false, true)

	CardStyle = lipgloss.NewStyle().
		Width(22).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Background(surface)

	StatValueStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(primary)

	TableHeaderStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(primary).
		Padding(0, 1)

	TableCellStyle = lipgloss.NewStyle().
		Padding(0, 1)

	SelectedRowStyle = lipgloss.NewStyle().
		Background(surface).
		Foreground(primary).
		Padding(0, 1)

	StatusBadgeStyle = func(s string) lipgloss.Style {
		color := muted
		switch s {
		case "completed":
			color = success
		case "running", "in_progress":
			color = primary
		case "failed":
			color = danger
		case "pending":
			color = warning
		}
		return lipgloss.NewStyle().
			Foreground(color).
			Bold(true).
			Padding(0, 1)
	}

	HelpStyle = lipgloss.NewStyle().
		Foreground(textDim).
		Padding(0, 1)

	SecondaryTitleStyle = lipgloss.NewStyle().
		Foreground(secondary).
		Bold(true).
		MarginBottom(1)

	ErrorStyle = lipgloss.NewStyle().
		Foreground(danger).
		Bold(true)

	ActiveFilterStyle = lipgloss.NewStyle().
		Foreground(primary).
		Bold(true).
		Padding(0, 1)

	FilterStyle = lipgloss.NewStyle().
		Foreground(textDim).
		Padding(0, 1)
)
