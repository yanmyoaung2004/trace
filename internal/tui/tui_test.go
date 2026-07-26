package tui

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yanmyoaung2004/trace/internal/playbook"
)

var errTest = errors.New("test error")

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

// --- Root model tests ---

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
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm, _ := updated.(*rootModel)
	if nm.active != investigationsScreen {
		t.Errorf("after tab: active = %v, want investigationsScreen", nm.active)
	}
	updated, _ = nm.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	nm = updated.(*rootModel)
	if nm.active != dashboardScreen {
		t.Errorf("after shift+tab: active = %v, want dashboardScreen", nm.active)
	}
}

func TestRootModelWindowSize(t *testing.T) {
	m := newRootModel(&mockApp{})
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	nm, _ := updated.(*rootModel)
	if nm.width != 120 {
		t.Errorf("width = %d", nm.width)
	}
	if nm.height != 40 {
		t.Errorf("height = %d", nm.height)
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

// --- Dashboard sub-model tests ---

func TestDashboardModel_Init(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd from Init")
	}
}

func TestDashboardModel_Load(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	updated, cmd := m.Update(dashboardLoaded{invs: nil})
	dm, ok := updated.(*dashboardModel)
	if !ok {
		t.Fatal("expected dashboardModel")
	}
	if dm.loading {
		t.Error("expected loading=false after load")
	}
	if cmd != nil {
		t.Error("expected nil cmd after load")
	}
}

func TestDashboardModel_LoadError(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	updated, _ := m.Update(dashboardLoaded{err: errTest})
	dm, _ := updated.(*dashboardModel)
	if dm.err == nil {
		t.Error("expected error to be set")
	}
}

func TestDashboardModel_Reload(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.loading = false
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	dm, _ := updated.(*dashboardModel)
	if !dm.loading {
		t.Error("expected loading=true after reload key")
	}
	if cmd == nil {
		t.Error("expected non-nil cmd after reload")
	}
}

func TestDashboardModel_WindowSize(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.Update(tea.WindowSizeMsg{Width: 100})
	if m.width != 100 {
		t.Errorf("width = %d", m.width)
	}
}

func TestDashboardModel_View(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.loading = false
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}

func TestDashboardModel_ViewLoading(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.loading = true
	v := m.View()
	if v == "" {
		t.Error("expected non-empty loading view")
	}
}

// --- Cases sub-model tests ---

func TestCasesModel_Init(t *testing.T) {
	m := newCasesModel(&mockApp{})
	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd")
	}
}

func TestCasesModel_Load(t *testing.T) {
	m := newCasesModel(&mockApp{})
	updated, _ := m.Update(casesLoaded{cases: nil})
	cm, ok := updated.(*casesModel)
	if !ok {
		t.Fatal("expected casesModel")
	}
	if cm.loading {
		t.Error("expected loading=false after load")
	}
}

func TestCasesModel_Navigation(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.cases = []Case{{ID: "case-1", Title: "Test Case"}}

	// Down arrow
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	cm, _ := updated.(*casesModel)
	if cm.cursor != 0 {
		t.Errorf("cursor = %d (wrapped to 0 since only 1 item)", cm.cursor)
	}
}

func TestCasesModel_View(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}

// --- Investigations sub-model tests ---

func TestInvestigationsModel_Init(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd")
	}
}

func TestInvestigationsModel_Load(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	updated, _ := m.Update(invsLoaded{invs: nil})
	im, ok := updated.(*investigationsModel)
	if !ok {
		t.Fatal("expected investigationsModel")
	}
	if im.loading {
		t.Error("expected loading=false after load")
	}
}

func TestInvestigationsModel_View(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	m.loading = false
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}

// --- SIEM sub-model tests ---

func TestSiemModel_Init(t *testing.T) {
	m := newSiemModel(&mockApp{})
	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd")
	}
}

func TestSiemModel_Load(t *testing.T) {
	m := newSiemModel(&mockApp{})
	updated, _ := m.Update(siemLoaded{})
	sm, ok := updated.(*siemModel)
	if !ok {
		t.Fatal("expected siemModel")
	}
	if sm.loading {
		t.Error("expected loading=false after load")
	}
}

func TestSiemModel_View(t *testing.T) {
	m := newSiemModel(&mockApp{})
	m.loading = false
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}

// --- Config sub-model tests ---

func TestConfigModel_Init(t *testing.T) {
	m := newConfigModel(&mockApp{})
	_ = m.Init() // config model doesn't load data, no cmd expected
}

func TestConfigModel_View(t *testing.T) {
	m := newConfigModel(&mockApp{})
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}
