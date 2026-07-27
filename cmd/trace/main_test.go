package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

var rootCmd = newRootCmd()

type cmdTestCase struct {
	name     string
	args     []string
	wantErr  bool
	contains []string
}

func executeCommand(root *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func runCmdTests(t *testing.T, tests []cmdTestCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeCommand(rootCmd, tt.args...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v\noutput:\n%s", err, tt.wantErr, output)
			}
			for _, s := range tt.contains {
				if !strings.Contains(output, s) {
					t.Errorf("expected output to contain %q:\n%s", s, output)
				}
			}
		})
	}
}

func TestVersionCmd(t *testing.T) {
	_ = t
}

func TestTSEMetrics(t *testing.T) {
	_ = t
}

func TestAllCommandsHelp(t *testing.T) {
	cmds := []string{
		"admin", "admin org", "admin org create", "admin org list",
		"admin user", "admin user create", "admin user list", "admin key",
		"approval", "approval list", "approval approve", "approval deny",
		"case", "case create", "case list", "case view",
		"case note", "case ioc", "case assign", "case close",
		"case export", "compliance", "compliance report", "compliance assess",
		"compliance evidence", "compliance list", "compliance trend",
		"edr", "edr agents", "edr agents view", "edr events", "edr vulns",
		"edr isolate", "edr release", "genkey", "history", "hunt",
		"hunt create", "hunt list", "hunt run", "hunt pause", "hunt resume", "hunt delete",
		"init", "investigate", "plugin", "plugin install", "plugin list",
		"plugin update", "plugin remove", "report", "serve", "server",
		"status", "tse", "tse status", "tse flush", "tse inspect",
		"tse snapshot", "tse metrics", "tse config show", "tse config set",
		"update", "update self", "update plugin", "update check", "version",
	}
	for _, name := range cmds {
		t.Run(name, func(t *testing.T) {
			args := strings.Split(name, " ")
			args = append(args, "--help")
			output, err := executeCommand(rootCmd, args...)
			if err != nil {
				t.Fatalf("err=%v\noutput:\n%s", err, output)
			}
			if output == "" {
				t.Errorf("empty help output for %s", name)
			}
		})
	}
}

func TestAllCommandsUnknownFlag(t *testing.T) {
	cmds := []struct {
		name string
		args []string
	}{
		{"serve", []string{"--bad-flag"}},
		{"server", []string{"--bad-flag"}},
		{"tse status", []string{"--bad-flag"}},
		{"case create", []string{"--bad-flag"}},
		{"hunt create", []string{"--bad-flag"}},
		{"compliance report", []string{"--bad-flag"}},
		{"edr agents", []string{"--bad-flag"}},
		{"admin org create", []string{"--bad-flag"}},
		{"admin user create", []string{"--bad-flag"}},
		{"plugin install", []string{"--bad-flag"}},
		{"genkey", []string{"--bad-flag"}},
		{"approval approve", []string{"--bad-flag"}},
		{"update check", []string{"--bad-flag"}},
		{"case export pdf", []string{"--bad-flag"}},
	}
	for _, c := range cmds {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{}, strings.Split(c.name, " ")...)
			args = append(args, c.args...)
			_, err := executeCommand(rootCmd, args...)
			if err == nil {
				t.Errorf("expected error for unknown flag in %s", c.name)
			}
		})
	}
}

func TestAllCommandsInvalidArg(t *testing.T) {
}

func TestAllCompletions(t *testing.T) {
	shells := []struct {
		name string
		fn   func(io.Writer) error
	}{
		{"bash", rootCmd.GenBashCompletion},
		{"zsh", rootCmd.GenZshCompletion},
	}
	for _, s := range shells {
		t.Run(s.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := s.fn(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if buf.Len() == 0 {
				t.Errorf("empty %s completion output", s.name)
			}
		})
	}

	// Fish completion has a different signature (includeDesc bool)
	t.Run("fish", func(t *testing.T) {
		var buf bytes.Buffer
		err := rootCmd.GenFishCompletion(&buf, true)
		if err != nil {
				t.Fatal(err)
		}
		if buf.Len() == 0 {
			t.Error("empty fish completion output")
		}
	})

	// PowerShell completion has a different signature
	t.Run("powershell", func(t *testing.T) {
		var buf bytes.Buffer
		err := rootCmd.GenPowerShellCompletion(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if buf.Len() == 0 {
			t.Error("empty powershell completion output")
		}
	})
}

func TestHelpGolden(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	if err := os.MkdirAll(goldenDir, 0755); err != nil {
		t.Fatal(err)
	}

	update := os.Getenv("UPDATE_GOLDEN") == "1"
	cmds := []string{
		"", "admin", "approval", "case", "compliance", "edr", "genkey",
		"history", "hunt", "init", "investigate", "plugin", "report",
		"serve", "server", "status", "tse", "update", "version",
	}

	for _, c := range cmds {
		t.Run("help_"+strings.ReplaceAll(c, " ", "_"), func(t *testing.T) {
			args := []string{"--help"}
			if c != "" {
				args = append([]string{c}, args...)
			}
			output, err := executeCommand(rootCmd, args...)
			if err != nil {
				t.Fatal(err)
			}

			goldenPath := filepath.Join(goldenDir, c+".txt")
			if c == "" {
				goldenPath = filepath.Join(goldenDir, "root.txt")
			}

			if update {
				if err := os.WriteFile(goldenPath, []byte(output), 0644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("golden file %s not found (set UPDATE_GOLDEN=1 to create): %v", goldenPath, err)
			}
			if output != string(want) {
				diff := diffHelp(output, string(want))
				t.Errorf("help output mismatch for %s\n%s", c, diff)
			}
		})
	}
}

func TestTSEConfigShowGolden(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	storagePath := strings.ReplaceAll(dir, "\\", "/")
	if err := os.WriteFile(cfgPath, []byte(`{"tse_storage_path":"`+storagePath+`"}`), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := executeCommand(rootCmd, "tse", "config", "show", "--config", cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	goldenDir := filepath.Join("testdata", "golden")
	goldenPath := filepath.Join(goldenDir, "tse_config_show.txt")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		os.MkdirAll(goldenDir, 0755)
		os.WriteFile(goldenPath, []byte(output), 0644)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("golden file not found: %v", err)
	}
	if output != string(want) {
		t.Errorf("output mismatch\n--- got\n+++ want\n%s", diffHelp(output, string(want)))
	}
}

func diffHelp(got, want string) string {
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(want, "\n")
	var b strings.Builder
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var g, w string
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g != w {
			fmt.Fprintf(&b, "-L%d: %s\n+L%d: %s\n", i+1, g, i+1, w)
		}
	}
	return b.String()
}

func containsAny(s string, substrs ...string) bool {
	s = strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
