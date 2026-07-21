package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/yanmyoaung2004/trace/internal/config"
	"github.com/yanmyoaung2004/trace/internal/db"
	"github.com/yanmyoaung2004/trace/internal/dispatch"
	"github.com/yanmyoaung2004/trace/internal/sift"
	"github.com/yanmyoaung2004/trace/internal/hunt"
	"github.com/yanmyoaung2004/trace/internal/integration/abuseipdb"
	"github.com/yanmyoaung2004/trace/internal/integration/edr"
	"github.com/yanmyoaung2004/trace/internal/integration/elastic"
	"github.com/yanmyoaung2004/trace/internal/integration/notifier"
	"github.com/yanmyoaung2004/trace/internal/integration/otx"
	"github.com/yanmyoaung2004/trace/internal/integration/splunk"
	"github.com/yanmyoaung2004/trace/internal/investigation"
	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/archive"
	"github.com/yanmyoaung2004/trace/internal/cases"
	"github.com/yanmyoaung2004/trace/internal/playbook"
	"github.com/yanmyoaung2004/trace/internal/plugin"
	"github.com/yanmyoaung2004/trace/internal/plugins/exporter"
	"github.com/yanmyoaung2004/trace/internal/plugins/sca"
	"github.com/yanmyoaung2004/trace/internal/response"
	"github.com/yanmyoaung2004/trace/internal/taskqueue"
	"github.com/yanmyoaung2004/trace/internal/telemetry"
	"github.com/yanmyoaung2004/trace/internal/tui"
	"github.com/spf13/cobra"
)

type App struct {
	cfg         *config.Config
	database    *db.DB
	sqlDB       *sql.DB
	registry    *plugin.Registry
	playbooks   *playbook.Engine
	executor    *playbook.Executor
	invManager  *investigation.Manager
	logWriter   *investigation.LogWriter
	taskQueue   *taskqueue.Queue
	dispatchAgent   *dispatch.Agent
	huntManager     *hunt.Manager
	huntScheduler   *hunt.Scheduler
	caseManager     *cases.Manager
	telemetry       *telemetry.Telemetry
}

func (a *App) ListPlaybooks() []*playbook.Playbook {
	if a.playbooks == nil {
		return nil
	}
	return a.playbooks.List()
}

func (a *App) ListCases(status, severity string) ([]tui.Case, error) {
	cs, err := a.caseManager.List(context.Background(), status, severity)
	if err != nil {
		return nil, err
	}
	res := make([]tui.Case, len(cs))
	for i, c := range cs {
		res[i] = tui.Case{
			ID:        c.ID,
			Title:     c.Title,
			Status:    c.Status,
			Severity:  c.Severity,
			Assignee:  c.Assignee,
			CreatedAt: c.CreatedAt,
		}
	}
	return res, nil
}

func (a *App) CreateCase(title, desc, severity string) (tui.Case, error) {
	c, err := a.caseManager.Create(context.Background(), title, desc, severity)
	if err != nil {
		return tui.Case{}, err
	}
	return tui.Case{
		ID:        c.ID,
		Title:     c.Title,
		Status:    c.Status,
		Severity:  c.Severity,
		CreatedAt: c.CreatedAt,
	}, nil
}

func (a *App) ViewCase(id string) (*tui.Case, error) {
	c, err := a.caseManager.Get(context.Background(), id)
	if err != nil {
		return nil, err
	}
	return &tui.Case{
		ID:        c.ID,
		Title:     c.Title,
		Status:    c.Status,
		Severity:  c.Severity,
		Assignee:  c.Assignee,
		CreatedAt: c.CreatedAt,
	}, nil
}

func (a *App) ListHunts(status string) ([]tui.Hunt, error) {
	hs, err := a.huntManager.List(context.Background(), status)
	if err != nil {
		return nil, err
	}
	res := make([]tui.Hunt, len(hs))
	for i, h := range hs {
		lr, nr := "—", "—"
		if h.LastRun != nil {
			lr = *h.LastRun
		}
		if h.NextRun != nil {
			nr = *h.NextRun
		}
		res[i] = tui.Hunt{
			ID:        h.ID,
			Name:      h.Name,
			Playbook:  h.Playbook,
			Schedule:  h.Schedule,
			Status:    h.Status,
			LastRun:   lr,
			NextRun:   nr,
			CreatedAt: h.CreatedAt,
		}
	}
	return res, nil
}

func (a *App) CreateHunt(name, desc, schedule, playbookName string) (tui.Hunt, error) {
	h, err := a.huntManager.Create(context.Background(), name, desc, schedule, playbookName, nil, "self", 0)
	if err != nil {
		return tui.Hunt{}, err
	}
	lr, nr := "—", "—"
	if h.LastRun != nil {
		lr = *h.LastRun
	}
	if h.NextRun != nil {
		nr = *h.NextRun
	}
	return tui.Hunt{
		ID:        h.ID,
		Name:      h.Name,
		Playbook:  h.Playbook,
		Schedule:  h.Schedule,
		Status:    h.Status,
		LastRun:   lr,
		NextRun:   nr,
		CreatedAt: h.CreatedAt,
	}, nil
}

func (a *App) RunHunt(name string) error {
	h, err := a.huntManager.GetByName(context.Background(), name)
	if err != nil {
		return err
	}
	a.huntScheduler.ExecuteNow(context.Background(), h)
	return nil
}

func (a *App) InvestigateInteractive(query, playbookName string) (tui.InvResult, error) {
	pb := a.playbooks.Get(playbookName)
	if pb == nil {
		return tui.InvResult{}, fmt.Errorf("playbook %q not found", playbookName)
	}

	inv, err := a.invManager.Create(context.Background(), query, playbookName)
	if err != nil {
		return tui.InvResult{}, fmt.Errorf("create investigation: %w", err)
	}

	params := extractParamsFromQuery(query)
	results, err := a.executor.Execute(context.Background(), inv, pb, params)
	if err != nil {
		return tui.InvResult{}, fmt.Errorf("execute playbook: %w", err)
	}

	reportOutput, err := a.dispatchAgent.Execute(context.Background(), agent.Input{
		"action":           "synthesize_report",
		"results":          results,
		"investigation_id": inv.ID,
		"intent":           query,
	})
	if err != nil {
		return tui.InvResult{}, fmt.Errorf("synthesize report: %w", err)
	}

	report, _ := reportOutput["report"].(string)
	return tui.InvResult{ID: inv.ID[:12], Report: report}, nil
}

var ipRegex    = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
var domainRegex = regexp.MustCompile(`\b([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
var hashRegex  = regexp.MustCompile(`\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b`)

func extractParamsFromQuery(query string) map[string]any {
	params := make(map[string]any)
	if m := ipRegex.FindString(query); m != "" {
		params["ip"] = m
		params["indicator"] = m
	}
	if m := hashRegex.FindString(query); m != "" {
		params["hash"] = m
		params["indicator"] = m
	}
	if m := domainRegex.FindString(query); m != "" {
		params["domain"] = m
		params["indicator"] = m
	}
	params["query"] = query
	return params
}

func (a *App) TotalInvestigations() int {
	ctx := context.Background()
	invs, _ := a.invManager.ListRecent(ctx, 10000)
	return len(invs)
}

func (a *App) OpenCases() int {
	cs, _ := a.caseManager.List(context.Background(), "", "")
	count := 0
	for _, c := range cs {
		if c.Status == "open" || c.Status == "investigating" {
			count++
		}
	}
	return count
}

func (a *App) ActiveHunts() int {
	hs, _ := a.huntManager.List(context.Background(), "")
	count := 0
	for _, h := range hs {
		if h.Status == "active" {
			count++
		}
	}
	return count
}

func (a *App) ListRecentInvestigations(limit int) ([]tui.InvBrief, error) {
	ctx := context.Background()
	invs, err := a.invManager.ListRecent(ctx, limit)
	if err != nil {
		return nil, err
	}
	res := make([]tui.InvBrief, len(invs))
	for i, inv := range invs {
		cf := 0.0
		if inv.Confidence != nil {
			cf = *inv.Confidence
		}
		res[i] = tui.InvBrief{
			ID:         inv.ID,
			Status:     inv.Status,
			Intent:     inv.Intent,
			Playbook:   inv.Playbook,
			Confidence: cf,
			CreatedAt:  inv.CreatedAt,
			UpdatedAt:  inv.UpdatedAt,
		}
	}
	return res, nil
}

func (a *App) ListInvestigations(status string) ([]tui.InvBrief, error) {
	return a.ListRecentInvestigations(1000)
}

func (a *App) SiemAlerts(count int) ([]string, error) {
	ctx := context.Background()
	invs, err := a.invManager.ListRecent(ctx, count)
	if err != nil {
		return nil, err
	}
	var alerts []string
	for _, inv := range invs {
		alerts = append(alerts, fmt.Sprintf("[%s] %s (%s)", inv.Status, inv.Intent, inv.ID[:8]))
	}
	return alerts, nil
}

func (a *App) ConfigValue(key string) string {
	if a.cfg == nil {
		return ""
	}
	switch key {
	case "db_path":
		return a.cfg.DBPath
	case "data_dir":
		return a.cfg.DataDir
	case "log_dir":
		return a.cfg.LogDir
	case "llm_provider":
		return a.cfg.LLMProvider
	case "llm_model":
		return a.cfg.LLMModel
	case "siem_enabled":
		return fmt.Sprintf("%v", a.cfg.SIEM.Enabled)
	case "server_addr":
		return a.cfg.Server.HTTPAddr
	default:
		return ""
	}
}

func (a *App) initConfig(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	a.cfg = cfg
	return nil
}

func (a *App) initDatabase() error {
	d, err := db.Open(a.cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	a.database = d
	a.sqlDB = d.DB
	return nil
}

func (a *App) initPlaybooks() error {
	a.playbooks = playbook.New()
	if err := a.playbooks.LoadBuiltin(); err != nil {
		return fmt.Errorf("load builtin playbooks: %w", err)
	}
	if err := a.playbooks.LoadDir(a.cfg.Playbook); err != nil {
		return fmt.Errorf("load playbook dir: %w", err)
	}
	return nil
}

func (a *App) initRegistry() error {
	a.registry = plugin.NewRegistry()

	a.registry.Register(sift.New(a.sqlDB, a.cfg.VTAPIKey))
	a.registry.Register(response.New(a.sqlDB))
	a.registry.Register(exporter.New(a.sqlDB))
	a.registry.Register(notifier.NewWithConfig(a.cfg.SlackWebhookURL, a.cfg.DiscordWebhookURL, a.cfg.TelegramBotToken, a.cfg.TelegramChatID))
	a.registry.Register(sca.New())
	a.registry.Register(edr.NewAgentFromConfig(edr.Config{Provider: "crowdstrike"}))
	a.registry.Register(abuseipdb.NewAgent(a.cfg.AbuseIPDBKey, a.sqlDB))
	a.registry.Register(otx.NewAgent(a.cfg.OTXAPIKey, a.sqlDB))
	a.registry.Register(splunk.New())
	a.registry.Register(elastic.New())

	a.dispatchAgent = dispatch.New(a.playbooks)
	if a.cfg.LLMURL != "" {
		planner := a.dispatchAgent.WithPlanner(a.cfg.LLMProvider, a.cfg.LLMURL, a.cfg.LLMAPIKey)
		if a.cfg.LLMModel != "" {
			planner.WithModel(a.cfg.LLMModel)
		}
	}
	a.registry.Register(a.dispatchAgent)

	mitreDB, err := archive.LoadMitreSeed()
	if err != nil {
		return fmt.Errorf("load mitre seed: %w", err)
	}
	archiveAgent := archive.New(a.sqlDB, mitreDB)
	if a.cfg.WebSearchKey != "" {
		archiveAgent.WithWebSearch(a.cfg.WebSearchKey)
	}
	a.registry.Register(archiveAgent)

	extDir := filepath.Join(filepath.Dir(a.cfg.DBPath), "plugins")
	extAgents, err := plugin.LoadDir(extDir)
	if err != nil {
		return fmt.Errorf("load external plugins: %w", err)
	}
	for _, ag := range extAgents {
		a.registry.Register(ag)
	}

	return nil
}

func (a *App) initServices() error {
	var err error
	a.invManager = investigation.NewManager(a.database)
	a.logWriter, err = investigation.NewLogWriter(a.cfg.LogDir)
	if err != nil {
		return fmt.Errorf("create log writer: %w", err)
	}
	a.taskQueue = taskqueue.New(a.database)
	a.executor = playbook.NewExecutor(a.registry, a.invManager, a.logWriter)
	a.huntManager = hunt.NewManager(a.database)
	a.huntScheduler = hunt.NewScheduler(a.huntManager, a.invManager, a.executor, a.playbooks, a.dispatchAgent, a.logWriter)
	a.caseManager = cases.NewManager(a.database)

	telURL := "https://telemetry.trace.sh/v1/report"
	if a.cfg.Telemetry.URL != "" {
		telURL = a.cfg.Telemetry.URL
	}
	a.telemetry = telemetry.New(a.cfg.Telemetry.Enabled, Version, telURL)
	a.telemetry.WithCounts(
		func() int { return len(a.registry.List()) },
		func() int {
			ctx := context.Background()
			invs, _ := a.invManager.ListRecent(ctx, 1000)
			return len(invs)
		},
	)

	return nil
}

func (a *App) initialize(cfgPath string) error {
	if err := a.initConfig(cfgPath); err != nil {
		return err
	}
	if err := a.initDatabase(); err != nil {
		return err
	}
	if err := a.initPlaybooks(); err != nil {
		return err
	}
	if err := a.initRegistry(); err != nil {
		return err
	}
	if err := a.initServices(); err != nil {
		return err
	}
	return nil
}

func persistentPre(cmd *cobra.Command, args []string) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if err := app.initialize(cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var app = &App{}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace — Multi-agent cybersecurity investigation platform",
		Long:  `Trace orchestrates security agents to investigate threats, enrich IOCs, analyze files, and automate response actions.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			return app.initialize(cmd.Flag("config").Value.String())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && tui.IsInteractive() {
				return tui.Start(app)
			}
			return cmd.Help()
		},
	}
	cmd.CompletionOptions.DisableDefaultCmd = false

	cmd.PersistentFlags().StringP("config", "c", "", "path to config file")

	invCmd := newInvestigateCmd()
	invCmd.Aliases = []string{"inv"}
	cmd.AddCommand(invCmd)

	statusCmd := newStatusCmd()
	statusCmd.Aliases = []string{"st"}
	cmd.AddCommand(statusCmd)

	historyCmd := newHistoryCmd()
	historyCmd.Aliases = []string{"hist"}
	cmd.AddCommand(historyCmd)

	cmd.AddCommand(newServeCmd())
	cmd.AddCommand(newApprovalCmd())
	cmd.AddCommand(newReportCmd())
	cmd.AddCommand(newGenKeyCmd())
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newPluginCmd())
	cmd.AddCommand(newServerCmd())
	cmd.AddCommand(newHuntCmd())
	cmd.AddCommand(newCaseCmd())
	cmd.AddCommand(newUpdateCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}
