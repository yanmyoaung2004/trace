package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type dashboardModel struct {
	app     App
	loading bool
	invs    []InvBrief
	err     error
	width   int
}

func newDashboardModel(app App) *dashboardModel {
	return &dashboardModel{app: app, loading: true}
}

func (m *dashboardModel) Init() tea.Cmd {
	return m.loadData
}

func (m *dashboardModel) loadData() tea.Msg {
	invs, err := m.app.ListRecentInvestigations(10)
	if err != nil {
		return dashboardLoaded{err: err}
	}
	return dashboardLoaded{invs: invs}
}

type dashboardLoaded struct {
	invs []InvBrief
	err  error
}

func (m *dashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case dashboardLoaded:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.invs = msg.invs
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			m.loading = true
			return m, m.loadData
		}
	}
	return m, nil
}

func (m *dashboardModel) View() string {
	if m.loading {
		return DocStyle.Render("Loading dashboard...")
	}

	totalInvs := m.app.TotalInvestigations()
	openCases := m.app.OpenCases()
	activeHunts := m.app.ActiveHunts()

	cards := lipgloss.JoinHorizontal(
		lipgloss.Top,
		CardStyle.Render(
			lipgloss.JoinVertical(lipgloss.Left,
				"Total Investigations",
				StatValueStyle.Render(fmt.Sprintf("%d", totalInvs)),
			),
		),
		"  ",
		CardStyle.Render(
			lipgloss.JoinVertical(lipgloss.Left,
				"Open Cases",
				StatValueStyle.Render(fmt.Sprintf("%d", openCases)),
			),
		),
		"  ",
		CardStyle.Render(
			lipgloss.JoinVertical(lipgloss.Left,
				"Active Hunts",
				StatValueStyle.Render(fmt.Sprintf("%d", activeHunts)),
			),
		),
	)

	var body string
	body += TitleStyle.Render("Dashboard") + "\n"
	body += cards + "\n\n"
	body += SecondaryTitleStyle.Render("Recent Investigations") + "\n"

	if m.err != nil {
		body += ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err))
		return DocStyle.Render(body)
	}

	if len(m.invs) == 0 {
		body += "  No investigations yet."
	} else {
		header := lipgloss.JoinHorizontal(
			lipgloss.Left,
			TableHeaderStyle.Width(10).Render("Status"),
			TableHeaderStyle.Width(36).Render("Intent"),
			TableHeaderStyle.Width(8).Render("Conf"),
			TableHeaderStyle.Width(20).Render("Created"),
		)
		body += header + "\n"
		body += strings.Repeat("─", m.width-4) + "\n"

		for _, inv := range m.invs {
			id := inv.ID
			if len(id) > 8 {
				id = id[:8]
			}
			status := StatusBadgeStyle(inv.Status).Render(inv.Status)
			intent := inv.Intent
			if len(intent) > 34 {
				intent = intent[:33] + "…"
			}
			cf := fmt.Sprintf("%.0f%%", inv.Confidence*100)
			created := formatTime(inv.CreatedAt)

			row := lipgloss.JoinHorizontal(
				lipgloss.Left,
				TableCellStyle.Width(10).Render(status),
				TableCellStyle.Width(36).Render(intent),
				TableCellStyle.Width(8).Render(cf),
				TableCellStyle.Width(20).Render(created),
			)
			body += row + "\n"
		}
	}

	return DocStyle.Render(body)
}
