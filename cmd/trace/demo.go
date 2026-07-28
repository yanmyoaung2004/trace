package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/config"
	"github.com/yanmyoaung2004/trace/internal/db"
	"github.com/yanmyoaung2004/trace/internal/edr_agent"
	"github.com/yanmyoaung2004/trace/internal/server"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/sqlite"
)

func newDemoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Start a demo environment (server + agent + test data)",
		Long: `Starts a full Trace demo on your machine:
- Server with web dashboard
- EDR agent monitoring local system
- TSE storage engine with sample events
- SIEM-like test data feed

Use --port to change the HTTP port (default: 8443).`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			log.SetOutput(os.Stderr)
			dir, _ := cmdCobra.Flags().GetString("data-dir")
			port, _ := cmdCobra.Flags().GetString("port")

			if dir == "" {
				home, _ := os.UserHomeDir()
				dir = filepath.Join(home, ".trace-demo")
			}
			if port == "" {
				port = "8443"
			}
			addr := ":" + port
			os.MkdirAll(dir, 0755)

			cfg := config.Default()
			cfg.DBPath = filepath.Join(dir, "trace.db")
			cfg.DataDir = dir
			cfg.LogDir = filepath.Join(dir, "logs")
			cfg.Server.HTTPAddr = addr
			cfg.Server.Enabled = true

			os.WriteFile(filepath.Join(dir, "config.json"), []byte(fmt.Sprintf(`{"server":{"http_addr":"%s"}}`, addr)), 0644)

			os.MkdirAll(cfg.LogDir, 0755)

			database, err := db.Open(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("db: %w", err)
			}
			defer database.Close()

			// Start server
			mgr := server.NewServerManager(database)
			if err := mgr.Migrate(); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}

			// Init TSE hot store for demo
			tsePath := filepath.Join(dir, "tse")
			os.MkdirAll(tsePath, 0755)
			hot, err := sqlite.NewSQLiteHotStore(filepath.Join(tsePath, "hot.db"))
			if err != nil {
				return fmt.Errorf("tse: %w", err)
			}
			defer hot.Close()

			tseWriter := &demoTSEReader{hot: hot}

			// Start HTTP server
			srv, err := server.ServeHTTP(server.ServeOptions{
				ListenAddr: addr,
				LogDir:     cfg.LogDir,
				DataDir:    dir,
				DB:         database.DB,
				TSEWriter:  tseWriter,
			}, mgr, mgr)
			if err != nil {
				return fmt.Errorf("serve: %w", err)
			}

			// Write some demo events to TSE
			go feedDemoEvents(hot)

			// Start demo agent (monitors /tmp)
			agentCfg := edr_agent.DefaultConfig()
			agentCfg.ServerURL = fmt.Sprintf("http://127.0.0.1:%s", port)
			agentCfg.DataDir = filepath.Join(dir, "agent-data")
			agentCfg.MonitorProcess = false
			agentCfg.MonitorFile = true
			agentCfg.MonitorNetwork = false
			agentCfg.WatchPaths = []string{dir, "/tmp"}
			agentCfg.ExcludePaths = []string{".db", ".db-wal", ".db-shm", ".log"}
			agentCfg.HeartbeatInterval = 15 * time.Second
			agentCfg.BatchInterval = 2 * time.Second
			agentCfg.MaxBatchSize = 50

			agent := edr_agent.New(agentCfg)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if err := agent.Start(ctx); err != nil {
				return fmt.Errorf("agent start: %w", err)
			}
			defer agent.Stop(context.Background())

			fmt.Println()
			fmt.Println("=== Trace Demo ===")
			fmt.Println()
			fmt.Printf("  Web UI:    http://localhost:%s\n", port)
			fmt.Printf("  Data dir:  %s\n", dir)
			fmt.Println()
			fmt.Println("  Demo agent is monitoring /tmp for file changes.")
			fmt.Println("  Try creating a file: echo test > /tmp/demo-test.txt")
			fmt.Println()
			fmt.Println("  Press Ctrl+C to stop.")
			fmt.Println()

			// Wait for signal
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh

			fmt.Println("\nShutting down demo...")
			srv.Close()
			return nil
		},
	}

	cmd.Flags().String("data-dir", "", "Demo data directory (default: ~/.trace-demo)")
	cmd.Flags().String("port", "8443", "HTTP port for web dashboard")
	return cmd
}

type demoTSEReader struct {
	hot *sqlite.SQLiteHotStore
}

func (d *demoTSEReader) WriteEvents(ctx context.Context, events []*storage.Event) error {
	return d.hot.WriteBatch(ctx, events)
}

func feedDemoEvents(hot *sqlite.SQLiteHotStore) {
	ctx := context.Background()
	events := []*storage.Event{
		{ID: "demo-0001", TenantID: "demo", AgentID: "demo-agent", Timestamp: time.Now().UnixMicro(), EventType: "demo:start", Severity: 1, Hostname: "demo-host"},
		{ID: "demo-0002", TenantID: "demo", AgentID: "siem", Timestamp: time.Now().UnixMicro(), EventType: "alert:demo_alert", Severity: 7, Hostname: "demo-host"},
		{ID: "demo-0003", TenantID: "demo", AgentID: "demo-agent", Timestamp: time.Now().UnixMicro(), EventType: "demo:file_create", Severity: 3, Hostname: "demo-host"},
		{ID: "demo-0004", TenantID: "demo", AgentID: "demo-agent", Timestamp: time.Now().UnixMicro(), EventType: "demo:net_connect", Severity: 5, Hostname: "demo-host"},
	}
	// Write multiple times to create some history
	for i := 0; i < 10; i++ {
		offset := int64(i) * 1000
		for _, e := range events {
			e.Timestamp = time.Now().UnixMicro() - offset
		}
		if err := hot.WriteBatch(ctx, events); err != nil {
			log.Printf("[demo] feed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Printf("[demo] seeded %d demo events", len(events)*10)
}
