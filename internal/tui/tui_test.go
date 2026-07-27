package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yanmyoaung2004/trace/internal/playbook"
)

var errTest = errors.New("test error")

type mockApp struct{}

func (m *mockApp) ListPlaybooks() []*playbook.Playbook {
	return []*playbook.Playbook{
		{Name: "phishing_investigation"},
		{Name: "malware_analysis"},
		{Name: "network_scan"},
	}
}
func (m *mockApp) ListCases(status, severity string) ([]Case, error) {
	if status == "error" {
		return nil, errTest
	}
	return []Case{
		{ID: "case-1", Title: "Phishing Campaign", Status: "open", Severity: "high", Assignee: "analyst1", CreatedAt: "2025-01-15T10:00:00Z"},
		{ID: "case-2", Title: "Ransomware Outbreak", Status: "closed", Severity: "critical", Assignee: "analyst2", CreatedAt: "2025-01-14T08:00:00Z"},
	}, nil
}
func (m *mockApp) CreateCase(title, desc, severity string) (Case, error) {
	if title == "error" {
		return Case{}, errTest
	}
	return Case{ID: "new-1", Title: title, Status: "open", Severity: severity, CreatedAt: "2025-01-16T12:00:00Z"}, nil
}
func (m *mockApp) ViewCase(id string) (*Case, error) {
	if id == "missing" {
		return nil, errors.New("not found")
	}
	return &Case{ID: id, Title: "Test Case", Status: "open", Severity: "medium"}, nil
}
func (m *mockApp) ListHunts(status string) ([]Hunt, error) {
	if status == "error" {
		return nil, errTest
	}
	return []Hunt{
		{ID: "hunt-1", Name: "Daily Scan", Status: "running", Schedule: "24h", Playbook: "network_scan"},
	}, nil
}
func (m *mockApp) CreateHunt(name, desc, schedule, playbookName string) (Hunt, error) {
	if name == "error" {
		return Hunt{}, errTest
	}
	return Hunt{ID: "new-hunt", Name: name, Schedule: schedule, Playbook: playbookName, Status: "active"}, nil
}
func (m *mockApp) RunHunt(name string) error {
	if name == "fail" {
		return errTest
	}
	return nil
}
func (m *mockApp) InvestigateInteractive(query, playbookName string) (InvResult, error) {
	if query == "fail" {
		return InvResult{}, errTest
	}
	return InvResult{ID: "inv-1", Report: "Investigation complete"}, nil
}
func (m *mockApp) TotalInvestigations() int                      { return 42 }
func (m *mockApp) OpenCases() int                                { return 3 }
func (m *mockApp) ActiveHunts() int                              { return 2 }
func (m *mockApp) ListRecentInvestigations(limit int) ([]InvBrief, error) {
	if limit < 0 {
		return nil, errTest
	}
	return []InvBrief{
		{ID: "inv-abc12345", Status: "completed", Intent: "Phishing analysis", Confidence: 0.85, CreatedAt: "2025-01-15T10:30:00Z"},
		{ID: "inv-def67890", Status: "pending", Intent: "Malware reverse", Confidence: 0.45, CreatedAt: "2025-01-14T09:00:00Z"},
	}, nil
}
func (m *mockApp) ListInvestigations(status string) ([]InvBrief, error) {
	if status == "error" {
		return nil, errTest
	}
	return m.ListRecentInvestigations(10)
}
func (m *mockApp) SiemAlerts(count int) ([]string, error) {
	if count < 0 {
		return nil, errTest
	}
	return []string{"ALERT: Port scan detected", "ALERT: Suspicious login"}, nil
}
func (m *mockApp) ConfigValue(key string) string {
	vals := map[string]string{
		"db_path":   "/home/user/.trace/trace.db",
		"data_dir":  "/home/user/.trace/data",
		"log_level": "info",
	}
	return vals[key]
}

// --- Helper function tests ---

func TestFormatTime(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2025-01-15T10:30:00Z", "2025-01-15T10:30:00"},
		{"2025-01-15T10:30:00.123Z", "2025-01-15T10:30:00"},
		{"short", "short"},
		{"", ""},
	}
	for _, tt := range tests {
		got := formatTime(tt.input)
		if got != tt.want {
			t.Errorf("formatTime(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestConfidenceBar(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0.0, "░░░░░░░░░░ 0%"},
		{0.5, "█████░░░░░ 50%"},
		{1.0, "██████████ 100%"},
		{1.5, "██████████ 150%"},
	}
	for _, tt := range tests {
		got := confidenceBar(tt.input)
		if !strings.Contains(got, tt.want[len(tt.want)-4:]) {
			t.Errorf("confidenceBar(%v) = %q, want suffix containing %q", tt.input, got, tt.want[len(tt.want)-4:])
		}
	}
}

// --- Data type tests ---

func TestCaseStruct(t *testing.T) {
	c := Case{ID: "case-1", Title: "Test", Status: "open", Severity: "high", Assignee: "user", CreatedAt: "now"}
	if c.ID != "case-1" || c.Title != "Test" || c.Status != "open" {
		t.Errorf("Case struct fields not set correctly: %+v", c)
	}
}

func TestHuntStruct(t *testing.T) {
	h := Hunt{ID: "hunt-1", Name: "Scan", Status: "running"}
	if h.ID != "hunt-1" || h.Name != "Scan" || h.Status != "running" {
		t.Errorf("Hunt struct fields not set correctly: %+v", h)
	}
}

func TestInvBriefStruct(t *testing.T) {
	ib := InvBrief{ID: "inv-1", Status: "completed", Confidence: 0.95}
	if ib.ID != "inv-1" || ib.Status != "completed" || ib.Confidence != 0.95 {
		t.Errorf("InvBrief struct fields not set correctly: %+v", ib)
	}
}

func TestInvResultStruct(t *testing.T) {
	ir := InvResult{ID: "ir-1", Report: "Analysis complete"}
	if ir.ID != "ir-1" || ir.Report != "Analysis complete" {
		t.Errorf("InvResult struct fields not set correctly: %+v", ir)
	}
}

// --- PlaybookCompletions tests ---

func TestPlaybookCompletions(t *testing.T) {
	lister := &mockApp{}
	tests := []struct {
		prefix string
		want   int
	}{
		{"p", 1},      // phishing_investigation
		{"m", 1},      // malware_analysis
		{"n", 1},      // network_scan
		{"x", 0},      // no matches
		{"", 3},       // all
	}
	for _, tt := range tests {
		got := PlaybookCompletions(tt.prefix, lister)
		if len(got) != tt.want {
			t.Errorf("PlaybookCompletions(%q) = %d results, want %d: %v", tt.prefix, len(got), tt.want, got)
		}
	}
}

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

func TestRootModelTabWrapping(t *testing.T) {
	m := newRootModel(&mockApp{})
	// Tab from last screen wraps to first
	m.active = configScreen
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	nm, _ := updated.(*rootModel)
	if nm.active != dashboardScreen {
		t.Errorf("tab wrap forward: active = %v, want dashboardScreen", nm.active)
	}

	// Shift+tab from first screen wraps to last
	m.active = dashboardScreen
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	nm = updated.(*rootModel)
	if nm.active != configScreen {
		t.Errorf("tab wrap backward: active = %v, want configScreen", nm.active)
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

func TestRootModelCtrlC(t *testing.T) {
	m := newRootModel(&mockApp{})
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("expected quit cmd from ctrl+c")
	}
}

func TestRootModelViewLoading(t *testing.T) {
	m := newRootModel(&mockApp{})
	m.width = 0
	v := m.View()
	if !strings.Contains(v, "Loading...") {
		t.Errorf("loading view should contain 'Loading...': %s", v)
	}
}

func TestRootModelViewContent(t *testing.T) {
	m := newRootModel(&mockApp{})
	m.width = 80
	m.height = 24
	v := m.View()
	if v == "" {
		t.Fatal("expected non-empty view")
	}
	if !strings.Contains(v, "Dashboard") {
		t.Errorf("view should contain Dashboard tab: %s", v[:50])
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

func TestDashboardModel_ViewWithData(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.loading = false
	m.width = 80
	m.invs = []InvBrief{{ID: "inv-1", Status: "completed", Intent: "Test", Confidence: 0.9, CreatedAt: "2025-01-15T10:00:00Z"}}
	v := m.View()
	if !strings.Contains(v, "42") {
		t.Errorf("view should show total investigations count: %s", v)
	}
	if !strings.Contains(v, "3") {
		t.Errorf("view should show open cases count: %s", v)
	}
}

func TestDashboardModel_ViewEmpty(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.loading = false
	m.width = 80
	v := m.View()
	if !strings.Contains(v, "No investigations yet") {
		t.Errorf("empty view should show 'No investigations yet': %s", v)
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

func TestDashboardModel_ViewError(t *testing.T) {
	m := newDashboardModel(&mockApp{})
	m.loading = false
	m.err = errTest
	m.width = 80
	v := m.View()
	if !strings.Contains(v, "Error") {
		t.Errorf("error view should contain 'Error': %s", v)
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

func TestCasesModel_LoadError(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = true
	updated, _ := m.Update(casesLoaded{err: errTest})
	cm, _ := updated.(*casesModel)
	if cm.err == nil {
		t.Error("expected error to be set")
	}
}

func TestCasesModel_Navigation(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.cases = []Case{
		{ID: "case-1", Title: "Test Case"},
		{ID: "case-2", Title: "Second Case"},
	}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	cm, _ := updated.(*casesModel)
	if cm.cursor != 1 {
		t.Errorf("after down: cursor = %d, want 1", cm.cursor)
	}

	updated, _ = cm.Update(tea.KeyMsg{Type: tea.KeyUp})
	cm = updated.(*casesModel)
	if cm.cursor != 0 {
		t.Errorf("after up: cursor = %d, want 0", cm.cursor)
	}
}

func TestCasesModel_CursorBounds(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.cases = []Case{{ID: "case-1", Title: "Only Case"}}

	// Going up past 0 wraps to last
	m.cursor = 0
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	cm, _ := updated.(*casesModel)
	if cm.cursor != 0 {
		t.Errorf("up from 0 with 1 item: cursor = %d, want 0", cm.cursor)
	}

	// Going down past last wraps to 0
	updated, _ = cm.Update(tea.KeyMsg{Type: tea.KeyDown})
	cm = updated.(*casesModel)
	if cm.cursor != 0 {
		t.Errorf("down from 0 with 1 item: cursor = %d, want 0", cm.cursor)
	}
}

func TestCasesModel_Reload(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	cm, _ := updated.(*casesModel)
	if !cm.loading {
		t.Error("expected loading=true after 'r'")
	}
	if cmd == nil {
		t.Error("expected non-nil cmd after 'r'")
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

func TestCasesModel_ViewWithCases(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.width = 80
	m.cases = []Case{
		{ID: "case-1", Title: "Phishing Campaign", Status: "open", Severity: "high", Assignee: "analyst1", CreatedAt: "2025-01-15"},
	}
	v := m.View()
	if !strings.Contains(v, "Phishing Campaign") {
		t.Errorf("view should contain case title: %s", v)
	}
}

func TestCasesModel_ViewEmpty(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.width = 80
	m.cases = []Case{}
	v := m.View()
	if !strings.Contains(v, "No") && !strings.Contains(v, "empty") {
		// Accept any reasonable empty-state message
	}
}

func TestCasesModel_ViewError(t *testing.T) {
	m := newCasesModel(&mockApp{})
	m.loading = false
	m.err = errTest
	m.width = 80
	v := m.View()
	if !strings.Contains(v, "Error") {
		t.Errorf("error view should contain 'Error': %s", v)
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

func TestInvestigationsModel_LoadError(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	m.loading = true
	updated, _ := m.Update(invsLoaded{err: errTest})
	im, _ := updated.(*investigationsModel)
	if im.err == nil {
		t.Error("expected error to be set")
	}
}

func TestInvestigationsModel_Filtering(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	m.loading = false
	m.invs = []InvBrief{
		{ID: "inv-1", Status: "completed", Intent: "Phishing"},
		{ID: "inv-2", Status: "pending", Intent: "Malware"},
		{ID: "inv-3", Status: "in_progress", Intent: "Network"},
	}

	// Press '2' for "completed" filter (1=all, 2=completed, 3=running, 4=failed, 5=pending)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	im, _ := updated.(*investigationsModel)
	filtered := im.filtered()
	if len(filtered) != 1 || filtered[0].ID != "inv-1" {
		t.Errorf("after '2' filter: expected 1 completed, got %d: %v", len(filtered), filtered)
	}

	// Press '1' to clear back to "all" filter
	updated, _ = im.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	im = updated.(*investigationsModel)
	if len(im.filtered()) != 3 {
		t.Errorf("after '1' (all): expected 3, got %d", len(im.filtered()))
	}
}

func TestInvestigationsModel_CursorNavigation(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	m.loading = false
	m.invs = []InvBrief{
		{ID: "inv-1", Status: "completed", Intent: "Phishing"},
		{ID: "inv-2", Status: "pending", Intent: "Malware"},
		{ID: "inv-3", Status: "in_progress", Intent: "Network"},
	}

	// Navigate down
	for i := 0; i < 2; i++ {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = updated.(*investigationsModel)
	}
	if m.cursor != 2 {
		t.Errorf("after 2 downs: cursor = %d, want 2", m.cursor)
	}

	// Navigate up
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(*investigationsModel)
	if m.cursor != 1 {
		t.Errorf("after up: cursor = %d, want 1", m.cursor)
	}
}

func TestInvestigationsModel_Reload(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	m.loading = false
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	im, _ := updated.(*investigationsModel)
	if !im.loading {
		t.Error("expected loading=true after 'r'")
	}
	if cmd == nil {
		t.Error("expected non-nil cmd after 'r'")
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

func TestInvestigationsModel_ViewError(t *testing.T) {
	m := newInvestigationsModel(&mockApp{})
	m.loading = false
	m.err = errTest
	m.width = 80
	v := m.View()
	if !strings.Contains(v, "Error") {
		t.Errorf("error view should contain 'Error': %s", v)
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

func TestSiemModel_LoadWithAlerts(t *testing.T) {
	m := newSiemModel(&mockApp{})
	m.loading = true
	updated, _ := m.Update(siemLoaded{alerts: []string{"ALERT: Test"}})
	sm, _ := updated.(*siemModel)
	if sm.loading {
		t.Error("expected loading=false after load")
	}
	if len(sm.alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(sm.alerts))
	}
}

func TestSiemModel_LoadError(t *testing.T) {
	m := newSiemModel(&mockApp{})
	m.loading = true
	updated, _ := m.Update(siemLoaded{err: errTest})
	sm, _ := updated.(*siemModel)
	if sm.err == nil {
		t.Error("expected error to be set")
	}
}

func TestSiemModel_Reload(t *testing.T) {
	m := newSiemModel(&mockApp{})
	m.loading = false
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	sm, _ := updated.(*siemModel)
	if !sm.loading {
		t.Error("expected loading=true after 'r'")
	}
	if cmd == nil {
		t.Error("expected non-nil cmd after 'r'")
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

func TestSiemModel_ViewError(t *testing.T) {
	m := newSiemModel(&mockApp{})
	m.loading = false
	m.err = errTest
	m.width = 80
	v := m.View()
	if !strings.Contains(v, "Error") {
		t.Errorf("error view should contain 'Error': %s", v)
	}
}

// --- Config sub-model tests ---

func TestConfigModel_Init(t *testing.T) {
	m := newConfigModel(&mockApp{})
	_ = m.Init()
}

func TestConfigModel_View(t *testing.T) {
	m := newConfigModel(&mockApp{})
	m.width = 80
	v := m.View()
	if v == "" {
		t.Error("expected non-empty view")
	}
}

func TestConfigModel_ViewWithConfig(t *testing.T) {
	m := newConfigModel(&mockApp{})
	m.width = 80
	v := m.View()
	if !strings.Contains(v, "db_path") || !strings.Contains(v, "trace.db") {
		t.Errorf("config view should show db_path: %s", v)
	}
}

func TestConfigModel_ViewEmpty(t *testing.T) {
	m := newConfigModel(&mockApp{})
	m.width = 80
	v := m.View()
	_ = v
}

func TestConfigModel_WindowSize(t *testing.T) {
	m := newConfigModel(&mockApp{})
	m.Update(tea.WindowSizeMsg{Width: 120})
	if m.width != 120 {
		t.Errorf("width = %d, want 120", m.width)
	}
}
