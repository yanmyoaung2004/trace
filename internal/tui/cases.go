package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type casesModel struct {
	app     App
	loading bool
	cases   []Case
	err     error
	cursor  int
	detail  *Case
	width   int
}

func newCasesModel(app App) *casesModel {
	return &casesModel{app: app, loading: true}
}

func (m *casesModel) Init() tea.Cmd {
	return m.loadCases
}

func (m *casesModel) loadCases() tea.Msg {
	cs, err := m.app.ListCases("", "")
	if err != nil {
		return casesLoaded{err: err}
	}
	return casesLoaded{cases: cs}
}

type casesLoaded struct {
	cases []Case
	err   error
}

func (m *casesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case casesLoaded:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.cases = msg.cases
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
			if m.cursor < len(m.cases)-1 {
				m.cursor++
			}
		case "enter":
			if len(m.cases) > 0 && m.cursor < len(m.cases) {
				m.detail = &m.cases[m.cursor]
			}
		case "r":
			m.loading = true
			return m, m.loadCases
		}
	}
	return m, nil
}

func (m *casesModel) View() string {
	if m.loading {
		return DocStyle.Render("Loading cases...")
	}
	if m.detail != nil {
		return m.renderDetail()
	}

	var body string
	body += TitleStyle.Render("Cases") + "\n"

	if m.err != nil {
		body += ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err))
		return DocStyle.Render(body)
	}

	if len(m.cases) == 0 {
		body += "  No cases."
	} else {
		header := lipgloss.JoinHorizontal(
			lipgloss.Left,
			TableHeaderStyle.Width(10).Render("Status"),
			TableHeaderStyle.Width(36).Render("Title"),
			TableHeaderStyle.Width(10).Render("Severity"),
			TableHeaderStyle.Width(20).Render("Created"),
		)
		body += header + "\n"
		body += strings.Repeat("─", m.width-4) + "\n"

		for i, c := range m.cases {
			prefix := "  "
			rowStyle := TableCellStyle
			if i == m.cursor {
				prefix = "▸ "
				rowStyle = SelectedRowStyle
			}
			id := c.ID
			if len(id) > 8 {
				id = id[:8]
			}
			title := c.Title
			if len(title) > 34 {
				title = title[:33] + "…"
			}
			row := lipgloss.JoinHorizontal(
				lipgloss.Left,
				rowStyle.Width(10).Render(StatusBadgeStyle(c.Status).Render(c.Status)),
				rowStyle.Width(36).Render(title),
				rowStyle.Width(10).Render(c.Severity),
				rowStyle.Width(20).Render(formatTime(c.CreatedAt)),
			)
			body += prefix + row + "\n"
		}
	}
	return DocStyle.Render(body)
}

func (m *casesModel) renderDetail() string {
	c := m.detail
	id := c.ID
	if len(id) > 12 {
		id = id[:12]
	}
	body := fmt.Sprintf("Case: %s\n\n", id)
	body += fmt.Sprintf("Title:    %s\n", c.Title)
	body += fmt.Sprintf("Status:   %s\n", StatusBadgeStyle(c.Status).Render(c.Status))
	body += fmt.Sprintf("Severity: %s\n", c.Severity)
	if c.Assignee != "" {
		body += fmt.Sprintf("Assignee: %s\n", c.Assignee)
	}
	body += fmt.Sprintf("Created:  %s\n", formatTime(c.CreatedAt))

	body += "\nPress ESC to go back."
	return DocStyle.Render(body)
}
