package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/innoigniter/edge/internal/agent"
	"github.com/innoigniter/edge/internal/siem"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the investigation server daemon",
		Long: `Start the InnoIgniterAI daemon. Optionally enables SIEM log monitoring.
Examples:
  innoigniter serve
  innoigniter serve --siem
  innoigniter serve --siem --syslog-addr :514`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.initialize(cmd.Flag("config").Value.String()); err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			log.Printf("InnoIgniterAI v%s starting", Version)
			log.Printf("Database: %s", app.cfg.DBPath)

			siemEnabled, _ := cmd.Flags().GetBool("siem")
			if siemEnabled {
				siemCfg := siem.SIEMConfig{
					Enabled:       true,
					PollInterval:  "5s",
				}
				if addr, _ := cmd.Flags().GetString("syslog-addr"); addr != "" {
					siemCfg.SyslogUDPAddr = addr
				}
				if dirs, _ := cmd.Flags().GetStringSlice("log-dir"); len(dirs) > 0 {
					siemCfg.LogDirs = dirs
				}

				engine := siem.New(siemCfg)
				engine.OnAlert(func(alert *siem.Alert) {
					log.Printf("[ALERT] %s (severity: %d)", alert.Title, alert.Severity)
				})

				if err := engine.Start(ctx); err != nil {
					return fmt.Errorf("start SIEM engine: %w", err)
				}
				log.Printf("SIEM engine started")
				defer engine.Stop()
			}

			exportAddr, _ := cmd.Flags().GetString("export")
			if exportAddr != "" {
				exporterAgent := app.registry.Get("exporter")
				if exporterAgent != nil {
					exporterAgent.Execute(ctx, agent.Input{
						"action": "serve_reports",
						"addr":   exportAddr,
					})
					log.Printf("Report server started at http://%s", exportAddr)
				}
			}

			go func() {
				log.Printf("Task worker started")
				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						task, err := app.taskQueue.Claim(ctx)
						if err != nil {
							log.Printf("claim task: %v", err)
							continue
						}
						if task == nil {
							continue
						}
						ag := app.registry.Get(task.Agent)
						if ag == nil {
							app.taskQueue.Fail(ctx, task.ID, fmt.Sprintf("agent %q not found", task.Agent))
							continue
						}
						log.Printf("Executing task %s: %s/%s", task.ID[:8], task.Agent, task.Action)
						output, err := ag.Execute(ctx, task.Payload)
						if err != nil {
							app.taskQueue.Fail(ctx, task.ID, err.Error())
							log.Printf("Task %s failed: %v", task.ID[:8], err)
							continue
						}
						app.taskQueue.Complete(ctx, task.ID, output)
						log.Printf("Task %s completed", task.ID[:8])
					}
				}
			}()

			<-sigCh
			log.Printf("Shutting down...")
			cancel()
			log.Printf("Stopped")
			return nil
		},
	}

	cmd.Flags().Bool("siem", false, "enable SIEM log monitoring")
	cmd.Flags().String("syslog-addr", "", "syslog listener address (e.g. :514)")
	cmd.Flags().StringSlice("log-dir", nil, "directories to watch for log files")
	cmd.Flags().String("export", "", "start HTML report server on given address (e.g. :8080)")
	return cmd
}
