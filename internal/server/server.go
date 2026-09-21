package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yanmyoaung2004/trace/internal/config"
	"github.com/yanmyoaung2004/trace/internal/db"
	"github.com/yanmyoaung2004/trace/internal/investigation"
)

// seedKeyPath is the write-once admin key location (0600).
func seedKeyPath(dataDir string) string {
	if dataDir == "" {
		dataDir = "."
	}
	return filepath.Join(dataDir, "admin_api_key")
}

// writeOnceKeyFile persists the seed key with 0600 perms, refusing to
// overwrite an existing file (operator must delete explicitly to rotate).
func writeOnceKeyFile(dataDir, key string) error {
	path := seedKeyPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(key + "\n"); err != nil {
		return err
	}
	return f.Sync()
}

func RunServer(cfg *config.Config, database *db.DB, invMgr *investigation.Manager, tseWriter EventWriter) error {
	mgr := NewServerManager(database)
	if err := mgr.Migrate(); err != nil {
		return fmt.Errorf("server migrate: %w", err)
	}
	if key, err := mgr.SeedDefaultUser(context.Background()); err != nil {
		log.Printf("[server] seed user warning: %v", err)
	} else if key != "" {
		// Write-once 0600 file; never print the key to stdout (it would
		// land in shell history / CI logs).
		if err := writeOnceKeyFile(cfg.DataDir, key); err != nil {
			log.Printf("[server] seed key file: %v", err)
		} else {
			fmt.Printf("\n  Admin API key written to %s (0600, shown once — store it now).\n\n", seedKeyPath(cfg.DataDir))
		}
	}

	if err := mgr.SyncLocalInvestigations(context.Background(), invMgr); err != nil {
		log.Printf("[server] sync local investigations: %v", err)
	}

	httpAddr := cfg.Server.EffectiveAddr()

	log.Printf("[server] starting in server mode")
	log.Printf("[server] HTTP API + dashboard: %s", httpAddr)

	srv, err := ServeHTTP(ServeOptions{
		ListenAddr: httpAddr,
		CertFile:   cfg.Server.TLS.CertFile,
		KeyFile:    cfg.Server.TLS.KeyFile,
		LogDir:     cfg.LogDir,
		DataDir:    cfg.DataDir,
		DB:         database.DB,
		TSEWriter:  tseWriter,
	}, mgr, mgr)
	if err != nil {
		return fmt.Errorf("start HTTP server: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	startTime := time.Now()

	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mgr.staleNodeCheck(ctx)
			}
		}
	}()

	<-sigCh
	log.Printf("[server] shutting down...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)

	log.Printf("[server] stopped (uptime: %s)", time.Since(startTime).Round(time.Second))
	return nil
}

func (m *ServerManager) staleNodeCheck(ctx context.Context) {
	cutoff := time.Now().Add(-90 * time.Second).Format(time.RFC3339)
	result, err := m.db.ExecContext(ctx,
		`UPDATE server_nodes SET status = 'offline' WHERE last_heartbeat < ? AND status = 'active'`, cutoff)
	if err != nil {
		return
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		log.Printf("[server] marked %d node(s) as offline", n)
	}
}
