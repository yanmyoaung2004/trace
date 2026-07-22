package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yanmyoaung2004/trace/internal/edr_agent"
)

var version = "0.1.1"

func main() {
	var (
		configPath  = flag.String("config", "", "Path to config file")
		serverURL   = flag.String("server", "", "Trace server URL")
		apiKey      = flag.String("api-key", "", "API key for server authentication")
		installSvc  = flag.Bool("install", false, "Install as system service")
		uninstallSvc = flag.Bool("uninstall", false, "Remove system service")
		showVersion = flag.Bool("version", false, "Show version")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("trace-agent v%s\n", version)
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
		if err := installService(cfg); err != nil {
			log.Fatalf("install service: %v", err)
		}
		fmt.Println("Service installed")
		return
	}
	if *uninstallSvc {
		if err := uninstallService(); err != nil {
			log.Fatalf("uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled")
		return
	}

	if err := run(cfg); err != nil {
		log.Fatalf("agent: %v", err)
	}
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

	return cfg
}

func run(cfg *edr_agent.Config) error {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("[trace-agent] starting v%s", version)

	agent := edr_agent.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	log.Printf("[trace-agent] shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := agent.Stop(shutdownCtx); err != nil {
		log.Printf("[trace-agent] stop error: %v", err)
	}

	return nil
}

func installService(cfg *edr_agent.Config) error {
	return fmt.Errorf("service installation not yet implemented for this platform")
}

func uninstallService() error {
	return fmt.Errorf("service uninstallation not yet implemented for this platform")
}
