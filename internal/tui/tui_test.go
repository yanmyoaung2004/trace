package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yanmyoaung2004/trace/internal/playbook"
)

type mockApp struct{}

func (m *mockApp) ListPlaybooks() []*playbook.Playbook          { return nil }
func (m *mockApp) ListCases(status, severity string) ([]Case, error) { return nil, nil }
func (m *mockApp) CreateCase(title, desc, severity string) (Case, error) { return Case{}, nil }
func (m *mockApp) ViewCase(id string) (*Case, error)             { return nil, nil }
func (m *mockApp) ListHunts(status string) ([]Hunt, error)       { return nil, nil }
func (m *mockApp) CreateHunt(name, desc, schedule, playbook string) (Hunt, error) { return Hunt{}, nil }
func (m *mockApp) RunHunt(name string) error                     { return nil }
func (m *mockApp) InvestigateInteractive(query, playbookName string) (InvResult, error) { return InvResult{}, nil }
func (m *mockApp) TotalInvestigations() int                      { return 42 }
func (m *mockApp) OpenCases() int                                { return 3 }
func (m *mockApp) ActiveHunts() int                              { return 2 }
func (m *mockApp) ListRecentInvestigations(limit int) ([]InvBrief, error) { return nil, nil }
func (m *mockApp) ListInvestigations(status string) ([]InvBrief, error)   { return nil, nil }
func (m *mockApp) SiemAlerts(count int) ([]string, error)        { return nil, nil }
func (m *mockApp) ConfigValue(key string) string                 { return "" }

func TestNewProgram(t *testing.T) {
	p := NewProgram(&mockApp{})
	if p == nil {
		t.Fatal("expected non-nil program")
	}
}

func TestRootModelInit(t *testing.T) {
	m := newRootModel(&mockApp{})
	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd")
	}
}

func TestRootModelTabNavigation(t *testing.T) {
	m := newRootModel(&mockApp{})

	// Tab should cycle through screens
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	newModel, ok := updated.(*rootModel)
	if !ok {
		t.Fatal("expected rootModel")
	}
	if newModel.active != investigationsScreen {
		t.Errorf("after tab: active = %v, want investigationsScreen", newModel.active)
	}

	// Shift+tab should go back
	updated, _ = newModel.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	newModel = updated.(*rootModel)
	if newModel.active != dashboardScreen {
		t.Errorf("after shift+tab: active = %v, want dashboardScreen", newModel.active)
	}
}

func TestRootModelWindowSize(t *testing.T) {
	m := newRootModel(&mockApp{})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	newModel, ok := updated.(*rootModel)
	if !ok {
		t.Fatal("expected rootModel")
	}
	if newModel.width != 120 {
		t.Errorf("width = %d, want 120", newModel.width)
	}
	if newModel.height != 40 {
		t.Errorf("height = %d, want 40", newModel.height)
	}
}

func TestRootModelQuit(t *testing.T) {
	m := newRootModel(&mockApp{})
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Error("expected quit cmd")
	}
}

func TestRootModelView(t *testing.T) {
	m := newRootModel(&mockApp{})
	m.width = 80
	m.height = 24

	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}
