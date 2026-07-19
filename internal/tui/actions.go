package tui

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/yanmyoaung2004/trace/internal/playbook"
)

type Case struct {
	ID        string
	Title     string
	Status    string
	Severity  string
	Assignee  string
	CreatedAt string
}

type Hunt struct {
	ID        string
	Name      string
	Playbook  string
	Schedule  string
	Status    string
	LastRun   string
	NextRun   string
	CreatedAt string
}

type InvResult struct {
	ID     string
	Report string
}

type InvBrief struct {
	ID         string
	Status     string
	Intent     string
	Playbook   string
	Confidence float64
	CreatedAt  string
	UpdatedAt  string
}

type App interface {
	ListPlaybooks() []*playbook.Playbook
	ListCases(status, severity string) ([]Case, error)
	CreateCase(title, desc, severity string) (Case, error)
	ViewCase(id string) (*Case, error)
	ListHunts(status string) ([]Hunt, error)
	CreateHunt(name, desc, schedule, playbook string) (Hunt, error)
	RunHunt(name string) error
	InvestigateInteractive(query, playbookName string) (InvResult, error)

	TotalInvestigations() int
	OpenCases() int
	ActiveHunts() int
	ListRecentInvestigations(limit int) ([]InvBrief, error)
	ListInvestigations(status string) ([]InvBrief, error)

	SiemAlerts(count int) ([]string, error)
	ConfigValue(key string) string
}

func RunMainMenu(p Prompter, app App) error {
	opts := []string{"Investigate", "List Cases", "List Hunts", "Run Server", "Init Wizard", "Help", "Quit"}
	choice, err := p.Select("Trace — Main Menu", opts)
	if err != nil {
		return err
	}
	switch choice {
	case "Investigate":
		return RunInvestigate(p, app)
	case "List Cases":
		return runListCases(p, app)
	case "List Hunts":
		return runListHunts(p, app)
	case "Run Server":
		fmt.Println("Run: trace serve")
		return nil
	case "Init Wizard":
		fmt.Println("Run: trace init")
		return nil
	case "Help":
		fmt.Println("Run: trace --help")
		return nil
	case "Quit":
		os.Exit(0)
	}
	return nil
}

func RunInvestigate(p Prompter, app App) error {
	query, err := p.Input("What do you want to investigate?", "")
	if err != nil {
		return err
	}
	if query == "" {
		fmt.Println("No query provided.")
		return nil
	}

	playbooks := app.ListPlaybooks()
	selected := ""
	if len(playbooks) > 0 {
		pbNames := make([]string, len(playbooks))
		for i, pb := range playbooks {
			pbNames[i] = pb.Name
		}
		selected, err = p.Select("Select a playbook", pbNames)
		if err != nil {
			return err
		}
	}

	result, err := app.InvestigateInteractive(query, selected)
	if err != nil {
		return fmt.Errorf("investigation failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\nInvestigation ID: %s\n\n", result.ID)
	fmt.Println(result.Report)
	return nil
}

func RunCaseMenu(p Prompter, app App) error {
	opts := []string{"List Cases", "Create Case", "View Case", "Back"}
	choice, err := p.Select("Case Manager", opts)
	if err != nil {
		return err
	}
	switch choice {
	case "List Cases":
		return runListCases(p, app)
	case "Create Case":
		return runCreateCase(p, app)
	case "View Case":
		return runViewCase(p, app)
	case "Back":
		return nil
	}
	return nil
}

func runListCases(p Prompter, app App) error {
	cases, err := app.ListCases("", "")
	if err != nil {
		return fmt.Errorf("list cases: %w", err)
	}
	if len(cases) == 0 {
		fmt.Println("No cases found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tTitle\tStatus\tSeverity\tAssignee\tCreated")
	for _, c := range cases {
		as := c.Assignee
		if as == "" {
			as = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.ID, c.Title, c.Status, c.Severity, as, c.CreatedAt)
	}
	w.Flush()
	return nil
}

func runCreateCase(p Prompter, app App) error {
	title, err := p.Input("Case title", "")
	if err != nil || title == "" {
		return err
	}
	desc, _ := p.Input("Description (optional)", "")
	severities := []string{"low", "medium", "high", "critical"}
	severity, err := p.Select("Severity", severities)
	if err != nil {
		return err
	}

	c, err := app.CreateCase(title, desc, severity)
	if err != nil {
		return fmt.Errorf("create case: %w", err)
	}
	fmt.Printf("Case created: %s (%s)\n", c.ID, c.Title)
	return nil
}

func runViewCase(p Prompter, app App) error {
	cases, err := app.ListCases("", "")
	if err != nil {
		return fmt.Errorf("list cases: %w", err)
	}
	if len(cases) == 0 {
		fmt.Println("No cases to view.")
		return nil
	}
	caseOpts := make([]string, len(cases))
	caseMap := make(map[string]string)
	for i, c := range cases {
		label := fmt.Sprintf("%s — %s [%s/%s]", c.ID, c.Title, c.Status, c.Severity)
		caseOpts[i] = label
		caseMap[label] = c.ID
	}
	selected, err := p.Select("Select a case to view", caseOpts)
	if err != nil {
		return err
	}
	c, err := app.ViewCase(caseMap[selected])
	if err != nil {
		return fmt.Errorf("view case: %w", err)
	}
	fmt.Printf("Case: %s\n", c.ID)
	fmt.Printf("Title:      %s\n", c.Title)
	fmt.Printf("Status:     %s\n", c.Status)
	fmt.Printf("Severity:   %s\n", c.Severity)
	if c.Assignee != "" {
		fmt.Printf("Assignee:   %s\n", c.Assignee)
	}
	fmt.Printf("Created:    %s\n", c.CreatedAt)
	return nil
}

func RunHuntMenu(p Prompter, app App) error {
	opts := []string{"List Hunts", "Run Hunt", "Create Hunt", "Back"}
	choice, err := p.Select("Hunt Manager", opts)
	if err != nil {
		return err
	}
	switch choice {
	case "List Hunts":
		return runListHunts(p, app)
	case "Run Hunt":
		return runRunHunt(p, app)
	case "Create Hunt":
		return runCreateHunt(p, app)
	case "Back":
		return nil
	}
	return nil
}

func runListHunts(p Prompter, app App) error {
	hunts, err := app.ListHunts("")
	if err != nil {
		return fmt.Errorf("list hunts: %w", err)
	}
	if len(hunts) == 0 {
		fmt.Println("No hunts configured.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tName\tPlaybook\tSchedule\tStatus\tLast Run\tNext Run")
	for _, h := range hunts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			h.ID, h.Name, h.Playbook, h.Schedule, h.Status, h.LastRun, h.NextRun)
	}
	w.Flush()
	return nil
}

func runCreateHunt(p Prompter, app App) error {
	name, err := p.Input("Hunt name", "")
	if err != nil || name == "" {
		return err
	}
	schedule, err := p.Input("Schedule (e.g. 6h, 12h, 24h)", "24h")
	if err != nil {
		return err
	}

	playbooks := app.ListPlaybooks()
	var pbNames []string
	for _, pb := range playbooks {
		pbNames = append(pbNames, pb.Name)
	}
	playbookName, err := p.Select("Playbook", pbNames)
	if err != nil {
		return err
	}

	h, err := app.CreateHunt(name, "", schedule, playbookName)
	if err != nil {
		return fmt.Errorf("create hunt: %w", err)
	}
	fmt.Printf("Hunt %q created (ID: %s)\n", h.Name, h.ID)
	fmt.Printf("  Schedule: %s\n", h.Schedule)
	fmt.Printf("  Playbook: %s\n", h.Playbook)
	return nil
}

func runRunHunt(p Prompter, app App) error {
	hunts, err := app.ListHunts("")
	if err != nil {
		return fmt.Errorf("list hunts: %w", err)
	}
	if len(hunts) == 0 {
		fmt.Println("No hunts to run.")
		return nil
	}
	huntOpts := make([]string, len(hunts))
	huntMap := make(map[string]string)
	for i, h := range hunts {
		label := fmt.Sprintf("%s — %s [%s]", h.Name, h.Playbook, h.Status)
		huntOpts[i] = label
		huntMap[label] = h.Name
	}
	selected, err := p.Select("Select a hunt to run", huntOpts)
	if err != nil {
		return err
	}
	if err := app.RunHunt(huntMap[selected]); err != nil {
		return fmt.Errorf("run hunt: %w", err)
	}
	fmt.Printf("Hunt %q executed.\n", huntMap[selected])
	return nil
}

func PlaybookCompletions(prefix string, lister interface{ ListPlaybooks() []*playbook.Playbook }) []string {
	pbs := lister.ListPlaybooks()
	var matches []string
	for _, pb := range pbs {
		if strings.HasPrefix(pb.Name, prefix) {
			matches = append(matches, pb.Name)
		}
	}
	return matches
}
