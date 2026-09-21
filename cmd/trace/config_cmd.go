package main

// Config command: check / dump --effective / migrate.
// FIX_PLAN 1.1: `config check` + `config dump --effective` green.

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yanmyoaung2004/trace/internal/config"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and migrate configuration",
	}

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate config and show warnings",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			cfgPath := cmdCobra.Flag("config").Value.String()
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			res := cfg.Check()
			fmt.Println("config: valid")
			fmt.Println("precedence: TRACE_* > flag > file > DB(remote) > default")
			for _, w := range res.Warnings {
				fmt.Printf("warning: %s\n", w)
			}
			return nil
		},
	}

	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump effective config (secrets redacted)",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			effective, _ := cmdCobra.Flags().GetBool("effective")
			if !effective {
				return fmt.Errorf("usage: trace config dump --effective")
			}
			cfgPath := cmdCobra.Flag("config").Value.String()
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			data, err := cfg.DumpEffective()
			if err != nil {
				return err
			}
			fmt.Println(string(data))
			return nil
		},
	}
	dumpCmd.Flags().Bool("effective", false, "dump merged effective config")

	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Rewrite deprecated config keys",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			cfgPath := cmdCobra.Flag("config").Value.String()
			if cfgPath == "" {
				return fmt.Errorf("specify --config path to migrate")
			}
			applied, err := config.Migrate(cfgPath)
			if err != nil {
				return err
			}
			if len(applied) == 0 {
				fmt.Println("config: nothing to migrate")
				return nil
			}
			for _, a := range applied {
				fmt.Printf("migrated: %s\n", a)
			}
			return nil
		},
	}

	cmd.AddCommand(checkCmd, dumpCmd, migrateCmd)
	return cmd
}
