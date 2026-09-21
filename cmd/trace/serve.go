package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/agent"
	"github.com/yanmyoaung2004/trace/internal/cases"
	"github.com/yanmyoaung2004/trace/internal/edge"
	"github.com/yanmyoaung2004/trace/internal/integration/notifier"
	"github.com/yanmyoaung2004/trace/internal/siem"
	"github.com/yanmyoaung2004/trace/internal/storage"
)

// autoCaseLimiter bounds SIEM auto-case explosions per (rule, entity).
// Shaped to swap to DetectReliabilityFixer's shared limiter when wired
// centrally; same semantics (5/hour per pair).
var autoCaseLimiter = cases.NewRateLimiter(5, time.Hour)

// autoCaseSeverity maps the 0-10 SIEM scale onto one case-severity label.
func autoCaseSeverity(sev int) string {
	switch {
	case sev >= 8:
		return "critical"
	case sev >= 5:
		return "high"
	case sev >= 3:
		return "medium"
	default:
		return "low"
	}
}

// shortAlertID truncates IDs for logs without panicking on short IDs.
func shortAlertID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the investigation server daemon",
		Long: `Start the Trace daemon. Optionally enables SIEM log monitoring and TSE storage.
Examples:
  trace serve
  trace serve --siem
  trace serve --tse
  trace serve --siem --tse`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.initialize(cmd.Flag("config").Value.String()); err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			log.SetOutput(os.Stderr)
			log.Printf("Trace v%s starting", Version)
			log.Printf("Database: %s", app.cfg.DBPath)

			// Initialize TSE if enabled
			tseEnabled, _ := cmd.Flags().GetBool("tse")
			if tseEnabled {
				app.cfg.TSE.Enabled = true
				if role, _ := cmd.Flags().GetString("tse-node-role"); role != "" {
					app.cfg.TSE.NodeRole = role
				}
				if sp, _ := cmd.Flags().GetString("tse-storage-path"); sp != "" {
					app.cfg.TSE.StoragePath = sp
				}
				if c, _ := cmd.Flags().GetString("tse-compression"); c != "" {
					app.cfg.TSE.Compression = c
				}
				if l, _ := cmd.Flags().GetInt("tse-compression-level"); l > 0 {
					app.cfg.TSE.CompressionLevel = l
				}
				if s, _ := cmd.Flags().GetInt("tse-row-group-size"); s > 0 {
					app.cfg.TSE.RowGroupSize = s
				}
				if b, _ := cmd.Flags().GetString("tse-s3-bucket"); b != "" {
					app.cfg.TSE.S3Bucket = b
				}
				if e, _ := cmd.Flags().GetString("tse-s3-endpoint"); e != "" {
					app.cfg.TSE.S3Endpoint = e
				}
				if r, _ := cmd.Flags().GetString("tse-s3-region"); r != "" {
					app.cfg.TSE.S3Region = r
				}
				if ssl, _ := cmd.Flags().GetBool("tse-s3-ssl"); ssl {
					app.cfg.TSE.S3UseSSL = true
				}
				tse, err := initTSE(&app.cfg.TSE)
				if err != nil {
					return fmt.Errorf("init TSE: %w", err)
				}
				app.tse = tse

				// Wire TSE alerts through notifier if configured
				if app.cfg.HasAnyNotifier() {
					tse.Flusher.AlertFunc = func(msg string) {
						ntf := notifier.NewWithConfig(notifier.AgentConfig{
							SlackWebhookURL:     app.cfg.SlackWebhookURL,
							DiscordWebhookURL:   app.cfg.DiscordWebhookURL,
							TelegramBotToken:    app.cfg.TelegramBotToken,
							TelegramChatID:      app.cfg.TelegramChatID,
							SMTPHost:            app.cfg.SMTPHost,
							SMTPPort:            app.cfg.SMTPPort,
							SMTPUser:            app.cfg.SMTPUser,
							SMTPPassword:        app.cfg.SMTPPassword,
							SMTPFrom:            app.cfg.SMTPFrom,
							EmailTo:             app.cfg.EmailTo,
							PagerDutyRoutingKey: app.cfg.PagerDutyRoutingKey,
							WebhookURL:          app.cfg.WebhookURL,
						})
						ntf.Execute(context.Background(), agent.Input{"message": msg})
					}
				}

				app.tse.StartTSE()
				defer app.tse.StopTSE()
			}

			siemEnabled, _ := cmd.Flags().GetBool("siem")
			if siemEnabled {
				siemCfg := siem.SIEMConfig{
					Enabled:      true,
					PollInterval: "5s",
				}
				if addr, _ := cmd.Flags().GetString("syslog-addr"); addr != "" {
					siemCfg.SyslogUDPAddr = addr
				}
				if dirs, _ := cmd.Flags().GetStringSlice("log-dir"); len(dirs) > 0 {
					siemCfg.LogDirs = dirs
				}

				engine := siem.New(siemCfg)
				engine.OnAlert(func(alert *siem.Alert) {
					log.Printf("[ALERT] %s (severity: %d, rule: %s)", alert.Title, alert.Severity, alert.RuleID)
					// Write alert to TSE through the ingest queue (rate-limited)
					if app.tse != nil && app.tse.Queue != nil {
						id, err := uuid.NewV7()
						if err != nil {
							id, _ = uuid.NewRandom()
						}
						tseEvent := &storage.Event{
							ID:        id.String(),
							AgentID:   "siem",
							Timestamp: alert.CreatedAt.UnixMicro(),
							EventType: fmt.Sprintf("alert:%s", alert.RuleID),
							Severity:  alert.Severity,
							Hostname:  alert.Source,
						}
						if tseErr := app.tse.WriteEvents(ctx, []*storage.Event{tseEvent}); tseErr != nil {
							log.Printf("[siem] tse write: %v", tseErr)
						}
					}

					var alertCaseID string
					if alert.Severity >= 4 {
						entity, _ := alert.Event.Fields["client_ip"].(string)
						if entity == "" {
							entity, _ = alert.Event.Fields["host"].(string)
						}
						if !autoCaseLimiter.Allow(alert.RuleID, entity) {
							log.Printf("[ALERT] auto-case rate-limited: rule=%s entity=%s", alert.RuleID, entity)
						} else {
							caseTitle := fmt.Sprintf("SIEM: %s", alert.Title)
							c, err := app.caseManager.CreateScoped(context.Background(), "", caseTitle, alert.RuleID, autoCaseSeverity(alert.Severity))
							if err != nil {
								log.Printf("[ALERT] create case: %v", err)
							} else {
								alertCaseID = c.ID
								app.caseManager.AddEvent(context.Background(), c.ID, "alert", fmt.Sprintf("SIEM alert: %s (severity: %d)", alert.Title, alert.Severity), "siem")
								// Never record "<nil>" junk: only add the IOC when present.
								if entity != "" && entity != "<nil>" {
									app.caseManager.AddIOC(context.Background(), c.ID, "ip", entity, "")
								}
							}
						}
					}

					for _, action := range alert.Actions {
						go func(a siem.RuleAction, caseID string) {
							defer func() {
								if r := recover(); r != nil {
									log.Printf("[ALERT] panic executing playbook %s: %v", a.Playbook, r)
								}
							}()

							alertCtx, alertCancel := context.WithTimeout(context.Background(), 2*time.Minute)
							defer alertCancel()

							pb := app.playbooks.Get(a.Playbook)
							if pb == nil {
								log.Printf("[ALERT] playbook %q not found for rule %s", a.Playbook, alert.RuleID)
								return
							}

							params := siem.InterpolateParams(a.Params, alert.Event)
							inv, err := app.invManager.Create(alertCtx, alert.Title, a.Playbook)
							if err != nil {
								log.Printf("[ALERT] create investigation: %v", err)
								return
							}

							results, err := app.executor.Execute(alertCtx, inv, pb, params)
							if err != nil {
								log.Printf("[ALERT] playbook %s failed: %v", a.Playbook, err)
								app.invManager.UpdateStatus(alertCtx, inv.ID, "failed")
								return
							}

							reportOutput, err := app.dispatchAgent.Execute(alertCtx, agent.Input{
								"action":           "synthesize_report",
								"results":          results,
								"investigation_id": inv.ID,
								"intent":           alert.Title,
							})
							if err != nil {
								log.Printf("[ALERT] report synthesis failed: %v", err)
								return
							}

							if report, ok := reportOutput["report"].(string); ok && report != "" {
								log.Printf("[ALERT] investigation %s completed — playbook: %s", shortAlertID(inv.ID), a.Playbook)
							}

							if caseID != "" {
								cf := 0.0
								if inv.Confidence != nil {
									cf = *inv.Confidence
								}
								app.caseManager.AddEvent(context.Background(), caseID, "investigation",
									fmt.Sprintf("Investigation %s completed via playbook %s (confidence: %.0f%%)", shortAlertID(inv.ID), a.Playbook, cf*100), "siem")
								app.caseManager.LinkInvestigation(context.Background(), caseID, inv.ID)
							}
						}(action, alertCaseID)
					}
				})

				if err := engine.Start(ctx); err != nil {
					return fmt.Errorf("start SIEM engine: %w", err)
				}
				log.Printf("SIEM engine started")
				defer engine.Stop()
			}

			app.telemetry.Start()
			go app.huntScheduler.Start(ctx)

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

			serverAddr, _ := cmd.Flags().GetString("server-addr")
			var syncClient *edge.SyncClient
			if serverAddr != "" {
				sc := edge.NewSyncClient(serverAddr, app.invManager)
				if err := sc.Register(ctx); err != nil {
					log.Printf("[edge-sync] registration failed: %v", err)
				} else {
					sc.Start(ctx)
					syncClient = sc
					log.Printf("[edge-sync] syncing to server at %s", serverAddr)
				}
			}

			<-sigCh
			log.Printf("Shutting down...")
			cancel()
			if syncClient != nil {
				syncClient.Close()
			}
			log.Printf("Stopped")
			return nil
		},
	}

	cmd.Flags().Bool("siem", false, "enable SIEM log monitoring")
	cmd.Flags().Bool("tse", false, "enable Trace Storage Engine (columnar event store)")
	cmd.Flags().String("tse-node-role", "auto", "TSE node role: leader, follower, or auto (default)")
	cmd.Flags().String("tse-storage-path", "", "TSE data directory")
	cmd.Flags().String("tse-compression", "zstd", "Parquet compression (zstd, snappy, gzip, lz4, none)")
	cmd.Flags().Int("tse-compression-level", 0, "Parquet compression level (0=default)")
	cmd.Flags().Int("tse-row-group-size", 0, "Parquet row group size (default 1,000,000)")
	cmd.Flags().String("tse-s3-bucket", "", "S3 bucket for Parquet files (enables S3 cold storage)")
	cmd.Flags().String("tse-s3-endpoint", "", "S3/MinIO endpoint (e.g. minio:9000)")
	cmd.Flags().String("tse-s3-region", "", "S3 region (e.g. us-east-1)")
	cmd.Flags().Bool("tse-s3-ssl", false, "Use HTTPS for S3 connections")
	cmd.Flags().String("syslog-addr", "", "syslog listener address (e.g. :514)")
	cmd.Flags().StringSlice("log-dir", nil, "directories to watch for log files")
	cmd.Flags().String("export", "", "start HTML report server on given address (e.g. :8080)")
	cmd.Flags().String("tls-cert", "", "TLS certificate file")
	cmd.Flags().String("tls-key", "", "TLS private key file")
	cmd.Flags().Bool("tls-auto", false, "auto-generate self-signed TLS certificate")
	cmd.Flags().String("server-addr", "", "address of central server for edge sync (e.g. http://localhost:8080)")
	return cmd
}
