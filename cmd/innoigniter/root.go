package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/config"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/detection"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/host"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/integration/abuseipdb"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/integration/elastic"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/integration/notifier"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/integration/otx"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/integration/splunk"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/investigation"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/knowledge"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/playbook"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/plugin"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/plugins/exporter"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/response"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/taskqueue"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/telemetry"
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
	hostAgent   *host.Agent
	telemetry   *telemetry.Telemetry
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

	a.registry.Register(detection.New(a.sqlDB, a.cfg.VTAPIKey))
	a.registry.Register(response.New(a.sqlDB))
	a.registry.Register(exporter.New(a.sqlDB))
	a.registry.Register(notifier.New())
	a.registry.Register(abuseipdb.NewAgent(a.cfg.AbuseIPDBKey))
	a.registry.Register(otx.NewAgent(a.cfg.OTXAPIKey))
	a.registry.Register(splunk.New())
	a.registry.Register(elastic.New())

	a.hostAgent = host.New(a.playbooks)
	if a.cfg.LLMURL != "" && a.cfg.LLMAPIKey != "" {
		a.hostAgent.WithPlanner(a.cfg.LLMProvider, a.cfg.LLMURL, a.cfg.LLMAPIKey)
	}
	a.registry.Register(a.hostAgent)

	mitreDB, err := knowledge.LoadMitreSeed()
	if err != nil {
		return fmt.Errorf("load mitre seed: %w", err)
	}
	knowledgeAgent := knowledge.New(a.sqlDB, mitreDB)
	if a.cfg.WebSearchKey != "" {
		knowledgeAgent.WithWebSearch(a.cfg.WebSearchKey)
	}
	a.registry.Register(knowledgeAgent)

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

	telURL := "https://telemetry.innoigniter.io/v1/report"
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
		Use:   "innoigniter",
		Short: "InnoIgniterAI — Multi-agent cybersecurity investigation platform",
		Long:  `InnoIgniterAI orchestrates security agents to investigate threats, enrich IOCs, analyze files, and automate response actions.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			return app.initialize(cmd.Flag("config").Value.String())
		},
	}

	cmd.PersistentFlags().StringP("config", "c", "", "path to config file")

	cmd.AddCommand(newServeCmd())
	cmd.AddCommand(newInvestigateCmd())
	cmd.AddCommand(newStatusCmd())
	cmd.AddCommand(newHistoryCmd())
	cmd.AddCommand(newApprovalCmd())
	cmd.AddCommand(newReportCmd())
	cmd.AddCommand(newGenKeyCmd())
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newPluginCmd())
	cmd.AddCommand(newServerCmd())
	cmd.AddCommand(newUpdateCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}
