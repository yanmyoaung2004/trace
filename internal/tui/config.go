package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type configModel struct {
	app   App
	width int
}

func newConfigModel(app App) *configModel {
	return &configModel{app: app}
}

func (m *configModel) Init() tea.Cmd {
	return nil
}

func (m *configModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *configModel) View() string {
	var body string
	body += TitleStyle.Render("Configuration") + "\n\n"

	keys := []string{"db_path", "data_dir", "log_dir", "llm_provider", "llm_model", "siem_enabled", "server_addr"}
	for _, k := range keys {
		v := m.app.ConfigValue(k)
		body += fmt.Sprintf("  %-15s  %s\n", k+":", v)
	}

	body += "\n  Configuration is managed in ~/.trace/config.json"
	return DocStyle.Render(body)
}
