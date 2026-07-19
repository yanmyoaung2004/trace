package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type siemModel struct {
	app     App
	loading bool
	alerts  []string
	err     error
	width   int
}

func newSiemModel(app App) *siemModel {
	return &siemModel{app: app, loading: true}
}

func (m *siemModel) Init() tea.Cmd {
	return m.loadAlerts
}

func (m *siemModel) loadAlerts() tea.Msg {
	alerts, err := m.app.SiemAlerts(50)
	if err != nil {
		return siemLoaded{err: err}
	}
	return siemLoaded{alerts: alerts}
}

type siemLoaded struct {
	alerts []string
	err    error
}

func (m *siemModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case siemLoaded:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.alerts = msg.alerts
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "r":
			m.loading = true
			return m, m.loadAlerts
		}
	}
	return m, nil
}

func (m *siemModel) View() string {
	if m.loading {
		return DocStyle.Render("Loading SIEM alerts...")
	}

	var body string
	body += TitleStyle.Render("SIEM Alerts") + "\n"

	if m.err != nil {
		body += ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err))
		return DocStyle.Render(body)
	}

	if len(m.alerts) == 0 {
		body += "  No alerts. Start the SIEM engine with `trace serve --siem`."
	} else {
		body += fmt.Sprintf("  Recent (%d):\n\n", len(m.alerts))
		for _, a := range m.alerts {
			body += "  " + a + "\n"
		}
	}
	return DocStyle.Render(body)
}


