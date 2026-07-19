package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type screen int

const (
	dashboardScreen screen = iota
	investigationsScreen
	casesScreen
	siemScreen
	configScreen
)

type rootModel struct {
	app       App
	active    screen
	width     int
	height    int
	screens   map[screen]tea.Model
}

func NewProgram(app App) *tea.Program {
	return tea.NewProgram(newRootModel(app), tea.WithAltScreen())
}

func newRootModel(app App) *rootModel {
	return &rootModel{
		app:    app,
		active: dashboardScreen,
		screens: map[screen]tea.Model{
			dashboardScreen:      newDashboardModel(app),
			investigationsScreen: newInvestigationsModel(app),
			casesScreen:          newCasesModel(app),
			siemScreen:           newSiemModel(app),
			configScreen:         newConfigModel(app),
		},
	}
}

func (m *rootModel) Init() tea.Cmd {
	cmds := []tea.Cmd{
		m.screens[m.active].Init(),
	}
	return tea.Batch(cmds...)
}

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.active = (m.active + 1) % screen(len(m.screens))
		case "shift+tab":
			m.active = (m.active - 1 + screen(len(m.screens))) % screen(len(m.screens))
		}
	}

	var cmd tea.Cmd
	m.screens[m.active], cmd = m.screens[m.active].Update(msg)
	return m, cmd
}

func (m *rootModel) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	tabs := m.renderTabs()
	content := m.screens[m.active].View()
	help := m.renderHelp()

	return lipgloss.JoinVertical(
		lipgloss.Left,
		tabs,
		content,
		help,
	)
}

func (m *rootModel) renderTabs() string {
	tabs := []string{"Dashboard", "Investigations", "Cases", "SIEM", "Config"}
	var rendered []string
	for i, tab := range tabs {
		s := screen(i)
		if s == m.active {
			rendered = append(rendered, ActiveTabStyle.Render(tab))
		} else {
			rendered = append(rendered, TabStyle.Render(tab))
		}
	}
	line := lipgloss.JoinHorizontal(lipgloss.Top, rendered...)
	gap := m.width - lipgloss.Width(line) - 2
	if gap < 1 {
		gap = 1
	}
	return line + strings.Repeat("─", gap)
}

func (m *rootModel) renderHelp() string {
	h := "  [Tab] Next screen  [↑/↓] Navigate  [Enter] Select  [q] Quit"
	return StatusBarStyle.Width(m.width).Render(h)
}

func Start(app App) error {
	p := NewProgram(app)
	_, err := p.Run()
	return err
}

func formatTime(ts string) string {
	if len(ts) >= 19 {
		return ts[:19]
	}
	return ts
}

func confidenceBar(c float64) string {
	n := int(c * 10)
	if n > 10 {
		n = 10
	}
	filled := strings.Repeat("█", n)
	empty := strings.Repeat("░", 10-n)
	return fmt.Sprintf("%s%s %.0f%%", filled, empty, c*100)
}
