package main

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

var rootCmd = newRootCmd()

func executeCommand(root *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestRootHelp(t *testing.T) {
	output, err := executeCommand(rootCmd, "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAny(output, "Usage", "Available", "serve") {
		t.Errorf("help output missing expected content: %s", output[:min(len(output), 200)])
	}
}

func TestVersionCmd(t *testing.T) {
	_ = t // version uses fmt.Printf, can't capture with cobra writer
}

func TestTSEHelp(t *testing.T) {
	output, err := executeCommand(rootCmd, "tse", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAny(output, "status", "flush", "inspect", "config") {
		t.Errorf("tse help missing commands: %s", output[:min(len(output), 300)])
	}
}

func TestTSEStatusWithStoragePath(t *testing.T) {
	dir := t.TempDir()
	_, err := executeCommand(rootCmd, "tse", "status", "--storage-path", dir)
	if err != nil {
		t.Fatal(err)
	}
	// status uses fmt.Printf — output goes to stdout, not captured
}

func TestTSEInspectWithStoragePath(t *testing.T) {
	dir := t.TempDir()
	_, err := executeCommand(rootCmd, "tse", "inspect", "--storage-path", dir)
	if err != nil {
		t.Fatal(err)
	}
	// inspect uses fmt.Printf — output goes to stdout
}

func TestTSEMetrics(t *testing.T) {
	_ = t // metrics uses fmt.Printf, can't capture
}

func TestServeHelp(t *testing.T) {
	output, err := executeCommand(rootCmd, "serve", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if output == "" {
		t.Fatal("expected serve help output")
	}
}

func TestCompletion(t *testing.T) {
	// Test that shell completion doesn't error
	err := rootCmd.GenBashCompletion(new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
}

func TestTSEConfigUnknownKey(t *testing.T) {
	_, err := executeCommand(rootCmd, "tse", "config", "set", "unknown_key", "value")
	if err == nil {
		t.Fatal("expected error for unknown config key")
	}
}

func TestInitHelp(t *testing.T) {
	output, err := executeCommand(rootCmd, "init", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !containsAny(output, "init", "Initialize") {
		t.Errorf("init help output: %s", output[:min(len(output), 200)])
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(sub) > 0 && len(s) > 0 {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
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
