package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type investigationsModel struct {
	app     App
	loading bool
	invs    []InvBrief
	err     error
	cursor  int
	filter  string
	detail  *InvBrief
	width   int
}

func newInvestigationsModel(app App) *investigationsModel {
	return &investigationsModel{app: app, loading: true}
}

func (m *investigationsModel) Init() tea.Cmd {
	return m.loadInvestigations
}

func (m *investigationsModel) loadInvestigations() tea.Msg {
	invs, err := m.app.ListInvestigations("")
	if err != nil {
		return invsLoaded{err: err}
	}
	return invsLoaded{invs: invs}
}

type invsLoaded struct {
	invs []InvBrief
	err  error
}

var statusFilters = []string{"all", "completed", "running", "failed", "pending"}

func (m *investigationsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case invsLoaded:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.invs = msg.invs
		}
	case tea.KeyMsg:
		if m.detail != nil {
			switch msg.String() {
			case "esc", "enter", "backspace":
				m.detail = nil
			case "q", "ctrl+c":
				return m, tea.Quit
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.filtered())-1 {
				m.cursor++
			}
		case "enter":
			invs := m.filtered()
			if len(invs) > 0 && m.cursor < len(invs) {
				m.detail = &invs[m.cursor]
			}
		case "r":
			m.loading = true
			return m, m.loadInvestigations
		case "1", "2", "3", "4", "5":
			idx := int(msg.String()[0] - '1')
			if idx >= 0 && idx < len(statusFilters) {
				m.filter = statusFilters[idx]
				m.cursor = 0
			}
		}
	}
	return m, nil
}

func (m *investigationsModel) filtered() []InvBrief {
	if m.filter == "" || m.filter == "all" {
		return m.invs
	}
	var res []InvBrief
	for _, inv := range m.invs {
		if inv.Status == m.filter {
			res = append(res, inv)
		}
	}
	return res
}

func (m *investigationsModel) View() string {
	if m.loading {
		return DocStyle.Render("Loading investigations...")
	}

	if m.detail != nil {
		return m.renderDetail()
	}

	var body string
	body += TitleStyle.Render("Investigations") + "\n"
	body += m.renderFilters() + "\n"

	if m.err != nil {
		body += ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err))
		return DocStyle.Render(body)
	}

	invs := m.filtered()
	if len(invs) == 0 {
		body += "  No investigations found."
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

		for i, inv := range invs {
			prefix := "  "
			rowStyle := TableCellStyle
			if i == m.cursor {
				prefix = "▸ "
				rowStyle = SelectedRowStyle
			}

			id := inv.ID
			if len(id) > 8 {
				id = id[:8]
			}
			statusLabel := inv.Status
			statusStyle := StatusBadgeStyle(inv.Status).Render(statusLabel)
			intent := inv.Intent
			if len(intent) > 34 {
				intent = intent[:33] + "…"
			}
			cf := fmt.Sprintf("%.0f%%", inv.Confidence*100)
			created := formatTime(inv.CreatedAt)

			row := lipgloss.JoinHorizontal(
				lipgloss.Left,
				rowStyle.Width(10).Render(statusStyle),
				rowStyle.Width(36).Render(intent),
				rowStyle.Width(8).Render(cf),
				rowStyle.Width(20).Render(created),
			)
			body += prefix + row + "\n"
		}
	}

	return DocStyle.Render(body)
}

func (m *investigationsModel) renderFilters() string {
	var rendered []string
	for i, f := range statusFilters {
		label := f
		if f == m.filter || (m.filter == "" && f == "all") {
			rendered = append(rendered, ActiveFilterStyle.Render(label))
		} else {
			rendered = append(rendered, FilterStyle.Render(label))
		}
		if i < len(statusFilters)-1 {
			rendered = append(rendered, " ")
		}
	}
	return strings.Join(rendered, "")
}

func (m *investigationsModel) renderDetail() string {
	inv := m.detail
	id := inv.ID
	if len(id) > 12 {
		id = id[:12]
	}
	body := fmt.Sprintf("Investigation: %s\n\n", id)
	body += fmt.Sprintf("Status:     %s\n", StatusBadgeStyle(inv.Status).Render(inv.Status))
	body += fmt.Sprintf("Intent:     %s\n", inv.Intent)
	body += fmt.Sprintf("Playbook:   %s\n", inv.Playbook)
	body += fmt.Sprintf("Confidence: %.0f%%\n", inv.Confidence*100)
	body += fmt.Sprintf("Created:    %s\n", formatTime(inv.CreatedAt))
	body += fmt.Sprintf("Updated:    %s\n", formatTime(inv.UpdatedAt))
	body += "\nPress ESC to go back."

	return DocStyle.Render(body)
}
