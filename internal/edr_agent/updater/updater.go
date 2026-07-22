package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Updater struct {
	serverURL  string
	apiKey     string
	currentVer string
	dataDir    string
	client     *http.Client
}

type UpdateInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	ReleaseDate string `json:"release_date"`
	Changelog   string `json:"changelog,omitempty"`
	Required    bool   `json:"required"`
}

func New(serverURL, apiKey, currentVer, dataDir string) *Updater {
	return &Updater{
		serverURL:  serverURL,
		apiKey:     apiKey,
		currentVer: currentVer,
		dataDir:    dataDir,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

func (u *Updater) Check(ctx context.Context) (*UpdateInfo, error) {
	url := fmt.Sprintf("%s/api/v1/edr/update/check?version=%s&platform=%s&arch=%s",
		u.serverURL, u.currentVer, runtime.GOOS, runtime.GOARCH)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if u.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+u.apiKey)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("check update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info UpdateInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse update info: %w", err)
	}

	return &info, nil
}

func (u *Updater) Apply(ctx context.Context, info *UpdateInfo) error {
	if info.Version == u.currentVer {
		return nil
	}

	tmpDir := filepath.Join(u.dataDir, "updates")
	os.MkdirAll(tmpDir, 0700)

	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("trace-agent-%s%s", info.Version, binaryExt()))
	defer os.Remove(tmpFile)

	if err := u.downloadBinary(ctx, info.DownloadURL, tmpFile); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	if info.SHA256 != "" {
		if err := verifyChecksum(tmpFile, info.SHA256); err != nil {
			return fmt.Errorf("checksum: %w", err)
		}
	}

	if err := os.Chmod(tmpFile, 0755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	backupPath := currentExe + ".bak"
	os.Remove(backupPath)

	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := os.Rename(tmpFile, currentExe); err != nil {
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("swap binary failed, restored backup: %w", err)
	}

	os.Remove(backupPath)

	return nil
}

func (u *Updater) downloadBinary(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	if u.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+u.apiKey)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	if written < 1024*1024 {
		return fmt.Errorf("binary suspiciously small: %d bytes", written)
	}

	return nil
}

func verifyChecksum(file, expected string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("checksum mismatch: got %s, expected %s", got[:16], expected[:16])
	}
	return nil
}

func binaryExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func (u *Updater) CurrentVersion() string {
	return u.currentVer
}
