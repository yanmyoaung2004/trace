package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build artifacts (agent binaries for distribution)",
	}

	buildAgentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Cross-compile agent binary for all platforms",
		Long: `Builds trace-agent binaries for Linux (amd64, arm64) and Windows (amd64).
Binaries are placed in the output directory with versioned names.

Use --upload to copy them to the server's update directory for OTA distribution.`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			outDir, _ := cmdCobra.Flags().GetString("output")
			uploadDir, _ := cmdCobra.Flags().GetString("upload")
			version := "0.1.1"

			if outDir == "" {
				outDir = "dist"
			}
			os.MkdirAll(outDir, 0755)

			targets := []struct {
				os   string
				arch string
				ext  string
			}{
				{"linux", "amd64", ""},
				{"linux", "arm64", ""},
				{"windows", "amd64", ".exe"},
			}

			for _, t := range targets {
				ext := t.ext
				name := fmt.Sprintf("trace-agent-v%s-%s-%s%s", version, t.os, t.arch, ext)
				outPath := filepath.Join(outDir, name)

				outf(cmdCobra, "building %s...\n", name)

				buildCmd := exec.Command("go", "build",
					"-o", outPath,
					"-ldflags", fmt.Sprintf("-X github.com/yanmyoaung2004/trace/internal/edr_agent.Version=%s", version),
					"./cmd/trace-agent/",
				)
				buildCmd.Env = append(os.Environ(),
					"GOOS="+t.os,
					"GOARCH="+t.arch,
					"CGO_ENABLED=0",
				)
				buildCmd.Stdout = os.Stdout
				buildCmd.Stderr = os.Stderr

				if err := buildCmd.Run(); err != nil {
					return fmt.Errorf("build %s: %w", name, err)
				}

				outf(cmdCobra, "  -> %s\n", outPath)
			}

			// Upload to server update directory
			if uploadDir != "" {
				os.MkdirAll(uploadDir, 0755)
				entries, err := os.ReadDir(outDir)
				if err != nil {
					return fmt.Errorf("read output dir: %w", err)
				}
				for _, e := range entries {
					if e.IsDir() || !strings.Contains(e.Name(), "trace-agent") {
						continue
					}
					src := filepath.Join(outDir, e.Name())
					dst := filepath.Join(uploadDir, e.Name())
					data, err := os.ReadFile(src)
					if err != nil {
						return fmt.Errorf("read %s: %w", src, err)
					}
					if err := os.WriteFile(dst, data, 0755); err != nil {
						return fmt.Errorf("write %s: %w", dst, err)
					}
					outf(cmdCobra, "uploaded %s -> %s\n", e.Name(), uploadDir)
				}
			}

			return nil
		},
	}
	buildAgentCmd.Flags().StringP("output", "o", "dist", "Output directory for binaries")
	buildAgentCmd.Flags().String("upload", "", "Upload to server update directory")

	cmd.AddCommand(buildAgentCmd)
	return cmd
}
