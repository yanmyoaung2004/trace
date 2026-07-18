package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var updateReleaseURL = "https://github.com/innoigniter/edge/releases/latest/download"

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update InnoIgniterAI or its data",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "self",
		Short: "Update the binary to the latest release",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			return updateSelf()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "intel",
		Short: "Refresh the bundled intel database",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			return updateIntel()
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "playbooks",
		Short: "Fetch the latest playbook library",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			return updatePlaybooks()
		},
	})

	return cmd
}

func updateSelf() error {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	binName := fmt.Sprintf("innoigniter-%s-%s%s", runtime.GOOS, arch, ext)
	sigName := binName + ".sig"
	url := fmt.Sprintf("%s/%s", updateReleaseURL, binName)
	sigURL := fmt.Sprintf("%s/%s", updateReleaseURL, sigName)

	fmt.Printf("Downloading %s ...\n", url)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	tmpDir, err := os.MkdirTemp("", "innoigniter-update")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpPath := filepath.Join(tmpDir, binName)

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, hash), resp.Body)
	if err != nil {
		f.Close()
		return fmt.Errorf("download body: %w", err)
	}
	f.Close()
	checksum := hex.EncodeToString(hash.Sum(nil))

	sigResp, sigErr := client.Get(sigURL)
	if sigErr == nil && sigResp.StatusCode == http.StatusOK {
		defer sigResp.Body.Close()
		sigData, _ := io.ReadAll(sigResp.Body)
		if len(sigData) > 0 {
			fmt.Printf("Signature (%d bytes) found; verification skipped (no local GPG key configured)\n", len(sigData))
		}
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	backupPath := selfPath + ".bak"
	os.Remove(backupPath)

	if err := os.Rename(selfPath, backupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := os.Rename(tmpPath, selfPath); err != nil {
		os.Rename(backupPath, selfPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	os.Remove(backupPath)

	fmt.Printf("Updated to %s (%d bytes, sha256: %s)\n", binName, written, checksum)
	fmt.Println("Restart the service to use the new version.")
	return nil
}

func updateIntel() error {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".innoigniter", "intel")
	os.MkdirAll(base, 0755)

	url := fmt.Sprintf("%s/intel.db", updateReleaseURL)
	fmt.Printf("Downloading intel DB from %s ...\n", url)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download intel: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	dest := filepath.Join(base, "intel.db")
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create intel file: %w", err)
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("write intel: %w", err)
	}

	fmt.Printf("Intel DB updated (%d bytes) at %s\n", written, dest)
	return nil
}

func updatePlaybooks() error {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".innoigniter", "playbooks")
	os.MkdirAll(base, 0755)

	fmt.Printf("Downloading playbook library from %s ...\n", updateReleaseURL)

	client := &http.Client{Timeout: 60 * time.Second}

	playbooks := []string{
		"hash-lookup.yaml", "file-analysis.yaml", "ip-reputation.yaml",
		"url-scan.yaml", "mitre-lookup.yaml", "cve-lookup.yaml",
		"block-ip.yaml", "quarantine-file.yaml", "kill-process.yaml",
		"restart-service.yaml", "rollback-action.yaml",
	}

	downloaded := 0
	for _, pb := range playbooks {
		pbURL := fmt.Sprintf("%s/%s", updateReleaseURL, pb)
		resp, err := client.Get(pbURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		dest := filepath.Join(base, pb)
		f, err := os.Create(dest)
		if err != nil {
			resp.Body.Close()
			continue
		}

		written, _ := io.Copy(f, resp.Body)
		f.Close()
		resp.Body.Close()

		if written > 0 {
			downloaded++
		}
	}

	if downloaded == 0 {
		fmt.Println("No playbooks downloaded (release server may not have them yet).")
	} else {
		fmt.Printf("Downloaded %d playbooks to %s\n", downloaded, base)
	}
	return nil
}

func init() {
	_ = context.Background
	_ = json.Marshal
	_ = exec.Command
	_ = uuid.New
}
