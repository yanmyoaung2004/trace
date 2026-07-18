package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yanmyoaung2004/innoigniter-ai/internal/config"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/db"
	"github.com/yanmyoaung2004/innoigniter-ai/internal/investigation"
)

func RunServer(cfg *config.Config, database *db.DB, invMgr *investigation.Manager) error {
	mgr := NewServerManager(database)
	if err := mgr.Migrate(); err != nil {
		return fmt.Errorf("server migrate: %w", err)
	}

	httpAddr := cfg.Server.HTTPAddr
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	log.Printf("[server] starting in server mode")
	log.Printf("[server] HTTP API + dashboard: %s", httpAddr)

	srv, err := ServeHTTP(ServeOptions{
		ListenAddr: httpAddr,
		CertFile:   cfg.Server.TLS.CertFile,
		KeyFile:    cfg.Server.TLS.KeyFile,
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
