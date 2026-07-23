package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent"
	"github.com/yanmyoaung2004/trace/internal/edr_agent/service"
)

var version = "0.1.1"

func main() {
	var (
		configPath   = flag.String("config", "", "Path to config file")
		serverURL    = flag.String("server", "", "Trace server URL")
		apiKey       = flag.String("api-key", "", "API key for server authentication")
		installSvc   = flag.Bool("install", false, "Install as system service")
		uninstallSvc = flag.Bool("uninstall", false, "Remove system service")
		serviceMode  = flag.Bool("service", false, "Run as system service (used by SCM)")
		showVersion  = flag.Bool("version", false, "Show version")
		showStatus   = flag.Bool("status", false, "Show agent status")
		verbose      = flag.Bool("verbose", false, "Enable verbose logging")
	)
	_ = showStatus
	flag.Parse()

	if *showVersion {
		fmt.Printf("trace-agent v%s\n", version)
		return
	}

	if *showStatus {
		statusCfg := loadConfig(*configPath)
		status, err := readAgentStatus(statusCfg)
		if err != nil {
			log.Fatalf("status: %v", err)
		}
		fmt.Println(status)
		return
	}

	cfg := loadConfig(*configPath)

	if *serverURL != "" {
		cfg.ServerURL = *serverURL
	}
	if *apiKey != "" {
		cfg.APIKey = *apiKey
	}

	if *installSvc {
		exe, _ := os.Executable()
		if err := service.Install(exe); err != nil {
			log.Fatalf("install service: %v", err)
		}
		fmt.Println("Service installed and started")
		return
	}
	if *uninstallSvc {
		if err := service.Uninstall(); err != nil {
			log.Fatalf("uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled")
		return
	}

	if *serviceMode {
		runAgent(cfg, *verbose)
		return
	}

	runAgent(cfg, *verbose)
}

func readAgentStatus(cfg *edr_agent.Config) (string, error) {
	agentPath := filepath.Join(cfg.DataDir, "agent.json")
	data, err := os.ReadFile(agentPath)
	if err != nil {
		return "Agent not running (no registration file found)\n", nil
	}
	var meta struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("parse agent.json: %w", err)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Agent ID:     %s\n", meta.AgentID))
	b.WriteString(fmt.Sprintf("Version:      %s\n", version))
	b.WriteString(fmt.Sprintf("Server:       %s\n", cfg.ServerURL))
	b.WriteString(fmt.Sprintf("Data Dir:     %s\n", cfg.DataDir))

	// Read queue stats
	queuePath := filepath.Join(cfg.DataDir, "queue", "event_queue.db")
	if data, err := os.ReadFile(queuePath); err == nil {
		b.WriteString(fmt.Sprintf("Queue DB:     %d bytes\n", len(data)))
	} else {
		b.WriteString("Queue DB:     not found\n")
	}

	// Check if agent process is running
	b.WriteString(fmt.Sprintf("PID:          %d\n", os.Getpid()))
	b.WriteString("Status:       see server for live status\n")

	return b.String(), nil
}

func loadConfig(path string) *edr_agent.Config {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".trace-agent", "config.json")
	}

	cfg, err := edr_agent.LoadConfig(path)
	if err != nil {
		log.Printf("warning: config load: %v (using defaults)", err)
		cfg = edr_agent.DefaultConfig()
	}

	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("TRACE_AGENT_API_KEY")
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = os.Getenv("TRACE_AGENT_SERVER")
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}

	return cfg
}

func runAgent(cfg *edr_agent.Config, verbose bool) {
	if verbose {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	} else {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}
	log.Printf("[trace-agent] v%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)

	agent := edr_agent.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		log.Fatalf("start: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			log.Printf("[trace-agent] SIGHUP — reloading correlator rules")
			agent.ReloadCorrelator()
			continue
		}
		break
	}
	log.Printf("[trace-agent] shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := agent.Stop(shutdownCtx); err != nil {
		log.Printf("[trace-agent] stop error: %v", err)
	}

	log.Printf("[trace-agent] stopped")
}
