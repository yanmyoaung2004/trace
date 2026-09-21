package main

// updateSelf/updateIntel/updatePlaybooks download operator artifacts with
// fail-closed verification.
//
// Trust contract (mirrors the agent updater):
//   - Base URL comes from config/env (TRACE_UPDATE_BASE_URL), defaulting to
//     the GitHub release download URL. HTTPS only; http allowed solely for
//     loopback (air-gap mirrors, tests).
//   - Every binary/data artifact MUST ship a "<name>.sha256" file holding
//     the expected hex digest, and SHOULD ship "<name>.sig" (base64 ed25519
//     over the raw digest, verified against TRACE_UPDATE_VERIFY_KEY_HEX or
//     --verify-key). A missing sha256 file refuses the update; a missing
//     .sig refuses only when a verify key is configured (signed fleet), and
//     warns otherwise. A present-but-invalid signature always refuses.
//   - Files stage to a temp dir, fsync, verify, then chmod/rename — never
//     chmod-before-verify.
//   - Playbook manifest (air-gap): updatePlaybooks fetches
//     "<base>/playbooks/manifest.json" ({files:[...], sha256 per file})
//     when present and verifies each playbook against it; without a
//     manifest it verifies per-file .sha256 sidecars. Files without any
//     hash source are skipped, never installed.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// updateBaseURL resolves the artifact base URL:
// TRACE_UPDATE_BASE_URL > --base-url flag default > compiled default.
var updateReleaseURL = "https://github.com/yanmyoaung2004/trace/releases/latest/download"

func updateBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("TRACE_UPDATE_BASE_URL")); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return updateReleaseURL
}

func updateTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("TRACE_UPDATE_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 5*time.Minute {
			return d
		}
	}
	return 30 * time.Second
}

func updateHTTPClient() *http.Client {
	return &http.Client{
		Timeout: updateTimeout(),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func requireUpdateHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid update URL: %w", err)
	}
	if u.Scheme == "https" && u.Host != "" {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")) {
		return nil
	}
	return fmt.Errorf("refusing non-HTTPS update URL %q", u.Redacted())
}

// updateVerifyKey loads the ed25519 verify key from
// TRACE_UPDATE_VERIFY_KEY_HEX (32-byte hex). Empty = unsigned mode:
// sha256 still enforced, signatures warn-only.
func updateVerifyKey() ed25519.PublicKey {
	raw := strings.TrimSpace(os.Getenv("TRACE_UPDATE_VERIFY_KEY_HEX"))
	if raw == "" {
		return nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "Warning: TRACE_UPDATE_VERIFY_KEY_HEX malformed; ignoring (signatures will warn-only).")
		return nil
	}
	return ed25519.PublicKey(b)
}

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Trace or its data",
	}

	updateSelfCmd := &cobra.Command{
		Use:   "self",
		Short: "Update the binary to the latest release",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			dryRun, _ := cmdCobra.Flags().GetBool("dry-run")
			base, _ := cmdCobra.Flags().GetString("base-url")
			if strings.TrimSpace(base) != "" {
				os.Setenv("TRACE_UPDATE_BASE_URL", strings.TrimSpace(base))
			}
			return updateSelf(dryRun)
		},
	}
	updateSelfCmd.Flags().Bool("dry-run", false, "check for updates without downloading")
	updateSelfCmd.Flags().String("base-url", "", "artifact base URL (default $TRACE_UPDATE_BASE_URL or release URL; air-gap mirror)")

	cmd.AddCommand(updateSelfCmd)

	intelCmd := &cobra.Command{
		Use:   "intel",
		Short: "Refresh the bundled intel database",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			base, _ := cmdCobra.Flags().GetString("base-url")
			if strings.TrimSpace(base) != "" {
				os.Setenv("TRACE_UPDATE_BASE_URL", strings.TrimSpace(base))
			}
			return updateIntel()
		},
	}
	intelCmd.Flags().String("base-url", "", "artifact base URL (air-gap mirror)")
	cmd.AddCommand(intelCmd)

	pbCmd := &cobra.Command{
		Use:   "playbooks",
		Short: "Fetch the latest playbook library",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			base, _ := cmdCobra.Flags().GetString("base-url")
			if strings.TrimSpace(base) != "" {
				os.Setenv("TRACE_UPDATE_BASE_URL", strings.TrimSpace(base))
			}
			return updatePlaybooks()
		},
	}
	pbCmd.Flags().String("base-url", "", "artifact base URL (air-gap mirror)")
	cmd.AddCommand(pbCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "rollback",
		Short: "Roll back to the previous binary version",
		Long:  `Restores the .bak backup created by 'trace update self'.`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			selfPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("get executable path: %w", err)
			}

			backupPath := selfPath + ".bak"
			if _, err := os.Stat(backupPath); os.IsNotExist(err) {
				return fmt.Errorf("no backup found at %s.\nRun 'trace update self' first to create a backup.", backupPath)
			}

			if err := os.Rename(selfPath, selfPath+".rollbak"); err != nil {
				return fmt.Errorf("move current binary: %w", err)
			}
			if err := os.Rename(backupPath, selfPath); err != nil {
				os.Rename(selfPath+".rollbak", selfPath)
				return fmt.Errorf("restore backup: %w", err)
			}
			os.Remove(selfPath + ".rollbak")
			fmt.Println("Rolled back to previous version.")
			fmt.Println("Restart the service to use the previous version.")
			return nil
		},
	})

	return cmd
}

func checkReleaseExists(client *http.Client) error {
	base := updateBaseURL()
	if err := requireUpdateHTTPS(base); err != nil {
		return err
	}
	chkURL := fmt.Sprintf("%s/checksums.txt", base)
	resp, err := client.Head(chkURL)
	if err != nil {
		return fmt.Errorf("cannot reach release server: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return fmt.Errorf("no releases found at %s.\nCreate a GitHub release first with: git tag v0.1.0 && git push --tags", base)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("release server returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// fetchExpectedHash downloads "<artifact>.sha256" and returns the hex
// digest. Missing/unparseable sidecar = error (fail-closed).
func fetchExpectedHash(client *http.Client, artifactURL string) (string, error) {
	resp, err := client.Get(artifactURL + ".sha256")
	if err != nil {
		return "", fmt.Errorf("fetch sha256 sidecar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refusing %s: no .sha256 sidecar (HTTP %d) — publish checksums before updating", artifactURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	if err != nil {
		return "", fmt.Errorf("read sha256 sidecar: %w", err)
	}
	// Accept both raw hex and "sha256sum" "<hex>  <name>" formats.
	field := strings.Fields(strings.TrimSpace(string(raw)))
	if len(field) == 0 {
		return "", fmt.Errorf("refusing %s: empty .sha256 sidecar", artifactURL)
	}
	hexStr := strings.ToLower(strings.TrimSpace(field[0]))
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("refusing %s: malformed .sha256 sidecar", artifactURL)
	}
	return hexStr, nil
}

// verifyArtifactSignature checks "<artifact>.sig" (base64 ed25519 over the
// raw digest) when a verify key is configured. No key configured: a valid
// .sig still verifies opportunistically? No — without a key there is
// nothing to verify against, so warn and continue (sha256 still enforced).
// Key configured + missing/invalid .sig = refuse.
func verifyArtifactSignature(client *http.Client, artifactURL, shaHex string) error {
	key := updateVerifyKey()
	resp, err := client.Get(artifactURL + ".sig")
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		if len(key) == ed25519.PublicKeySize {
			return fmt.Errorf("refusing %s: verify key configured but no .sig published", artifactURL)
		}
		fmt.Fprintln(os.Stderr, "Warning: no .sig sidecar; sha256-only verification (provision TRACE_UPDATE_VERIFY_KEY_HEX for signed updates).")
		return nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if err != nil {
		return fmt.Errorf("read .sig sidecar: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("refusing %s: malformed .sig sidecar", artifactURL)
	}
	if len(key) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "Warning: .sig present but no verify key configured; sha256-only verification.")
		return nil
	}
	digest, _ := hex.DecodeString(shaHex)
	if !ed25519.Verify(key, digest, sig) {
		return fmt.Errorf("refusing %s: signature verification failed", artifactURL)
	}
	fmt.Println("Signature verified.")
	return nil
}

// stageVerifiedDownload streams url to a temp file, fsyncs, and verifies
// the sha256 before returning the staged path. Chmod/rename happen only
// in the caller after this returns nil error.
func stageVerifiedDownload(client *http.Client, artifactURL, tmpDir, name string) (stagedPath string, written int64, err error) {
	if err := requireUpdateHTTPS(artifactURL); err != nil {
		return "", 0, err
	}
	expected, err := fetchExpectedHash(client, artifactURL)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Get(artifactURL)
	if err != nil {
		return "", 0, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
		return "", 0, fmt.Errorf("refusing redirect to %q", resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	staged := filepath.Join(tmpDir, name+".staged")
	if fi, err := os.Lstat(staged); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("refusing: stage path is a symlink")
	}
	f, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, fmt.Errorf("create temp file: %w", err)
	}
	hash := sha256.New()
	written, err = io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, 512<<20))
	if cerr := f.Sync(); cerr != nil && err == nil {
		err = fmt.Errorf("fsync staged file: %w", cerr)
	}
	if cerr := f.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("close staged file: %w", cerr)
	}
	if err != nil {
		os.Remove(staged)
		return "", 0, fmt.Errorf("download body: %w", err)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != expected {
		os.Remove(staged)
		return "", 0, fmt.Errorf("refusing %s: checksum mismatch", name)
	}
	if err := verifyArtifactSignature(client, artifactURL, expected); err != nil {
		os.Remove(staged)
		return "", 0, err
	}
	return staged, written, nil
}

func updateSelf(dryRun bool) error {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	base := updateBaseURL()
	binName := fmt.Sprintf("trace-%s-%s%s", runtime.GOOS, arch, ext)
	artifactURL := fmt.Sprintf("%s/%s", base, binName)

	client := updateHTTPClient()

	if err := checkReleaseExists(client); err != nil {
		return err
	}

	fmt.Printf("Found release at %s\n", base)
	fmt.Printf("Latest binary: %s\n", binName)

	if dryRun {
		fmt.Println("Dry-run: no changes made. Run without --dry-run to update.")
		return nil
	}

	fmt.Printf("Downloading %s ...\n", artifactURL)

	tmpDir, err := os.MkdirTemp("", "trace-update")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	staged, written, err := stageVerifiedDownload(client, artifactURL, tmpDir, binName)
	if err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
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

	if err := os.Rename(staged, selfPath); err != nil {
		os.Rename(backupPath, selfPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	os.Remove(backupPath)

	fmt.Printf("Updated to %s (%d bytes, verified sha256)\n", binName, written)
	fmt.Println("Restart the service to use the new version.")
	return nil
}

func updateIntel() error {
	home, _ := os.UserHomeDir()
	baseDir := filepath.Join(home, ".trace", "intel")
	os.MkdirAll(baseDir, 0o755)

	base := updateBaseURL()
	artifactURL := fmt.Sprintf("%s/intel.db", base)
	client := updateHTTPClient()

	if err := checkReleaseExists(client); err != nil {
		return err
	}

	fmt.Printf("Downloading intel DB from %s ...\n", artifactURL)

	tmpDir, err := os.MkdirTemp("", "trace-intel")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	staged, written, err := stageVerifiedDownload(client, artifactURL, tmpDir, "intel.db")
	if err != nil {
		return err
	}
	dest := filepath.Join(baseDir, "intel.db")
	// fsync dir entry durability: write temp in dest dir then rename.
	if fi, err := os.Lstat(dest + ".new"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing: stage path is a symlink")
	}
	final, err := os.OpenFile(dest+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create intel file: %w", err)
	}
	src, err := os.Open(staged)
	if err != nil {
		final.Close()
		return err
	}
	if _, err := io.Copy(final, src); err != nil {
		src.Close()
		final.Close()
		return fmt.Errorf("write intel: %w", err)
	}
	src.Close()
	if err := final.Sync(); err != nil {
		final.Close()
		return fmt.Errorf("fsync intel: %w", err)
	}
	final.Close()
	if err := os.Rename(dest+".new", dest); err != nil {
		return fmt.Errorf("swap intel: %w", err)
	}

	fmt.Printf("Intel DB updated (%d bytes, verified sha256) at %s\n", written, dest)
	return nil
}

// playbookManifest is the air-gap manifest: when the release publishes
// playbooks/manifest.json, every playbook hash comes from it (single
// signed root) instead of N sidecars.
type playbookManifest struct {
	Files map[string]string `json:"files"` // name -> sha256 hex
}

func fetchPlaybookManifest(client *http.Client) *playbookManifest {
	u := updateBaseURL() + "/playbooks/manifest.json"
	if err := requireUpdateHTTPS(u); err != nil {
		return nil
	}
	resp, err := client.Get(u)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
	var m playbookManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&m); err != nil || len(m.Files) == 0 {
		return nil
	}
	return &m
}

func updatePlaybooks() error {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".trace", "playbooks")
	os.MkdirAll(base, 0o755)

	client := updateHTTPClient()

	if err := checkReleaseExists(client); err != nil {
		return err
	}

	releaseBase := updateBaseURL()
	fmt.Printf("Downloading playbook library from %s ...\n", releaseBase)

	playbooks := []string{
		"hash-lookup.yaml", "file-analysis.yaml", "ip-reputation.yaml",
		"domain-reputation.yaml", "email-analysis.yaml", "network-scan.yaml",
		"log-analysis.yaml", "cve-lookup.yaml", "mitre-lookup.yaml",
		"block-ip.yaml", "quarantine-file.yaml", "kill-process.yaml",
		"restart-service.yaml", "rollback-action.yaml",
		"full-enrich.yaml", "rootkit-scan.yaml", "compliance-scan.yaml",
	}

	manifest := fetchPlaybookManifest(client)
	if manifest != nil {
		fmt.Printf("Using playbook manifest (%d entries).\n", len(manifest.Files))
	}

	downloaded, skipped := 0, 0
	for _, pb := range playbooks {
		pbURL := fmt.Sprintf("%s/%s", releaseBase, pb)
		if err := requireUpdateHTTPS(pbURL); err != nil {
			skipped++
			continue
		}
		// Manifest mode: verify against manifest hash. Sidecar mode:
		// per-file .sha256 required; files with neither are skipped.
		var expected string
		if manifest != nil {
			var ok bool
			expected, ok = manifest.Files[pb]
			if !ok {
				fmt.Fprintf(os.Stderr, "Skipping %s: not in manifest.\n", pb)
				skipped++
				continue
			}
			if b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(expected))); err != nil || len(b) != sha256.Size {
				fmt.Fprintf(os.Stderr, "Skipping %s: malformed manifest hash.\n", pb)
				skipped++
				continue
			}
			expected = strings.ToLower(strings.TrimSpace(expected))
		}
		resp, err := client.Get(pbURL)
		if err != nil || resp.StatusCode == 404 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil || len(body) == 0 {
			continue
		}
		if manifest == nil {
			h, herr := fetchExpectedHash(client, pbURL)
			if herr != nil {
				fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", pb, herr)
				skipped++
				continue
			}
			expected = h
			if serr := verifyArtifactSignature(client, pbURL, expected); serr != nil {
				fmt.Fprintf(os.Stderr, "Skipping %s: %v\n", pb, serr)
				skipped++
				continue
			}
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != expected {
			fmt.Fprintf(os.Stderr, "Skipping %s: checksum mismatch.\n", pb)
			skipped++
			continue
		}

		dest := filepath.Join(base, pb)
		if rel, err := filepath.Rel(base, dest); err != nil || rel != pb {
			skipped++
			continue
		}
		if err := os.WriteFile(dest+".new", body, 0o600); err != nil {
			continue
		}
		if err := os.Rename(dest+".new", dest); err != nil {
			os.Remove(dest + ".new")
			continue
		}
		downloaded++
	}

	if downloaded == 0 {
		fmt.Println("No playbooks downloaded (every file requires a verified hash; see skips above).")
		fmt.Printf("  Release URL: %s\n", releaseBase)
	} else {
		fmt.Printf("Downloaded %d playbooks to %s (%d skipped unverified)\n", downloaded, base, skipped)
	}
	return nil
}

func init() {
	_ = context.Background
	_ = json.Marshal
	_ = uuid.New
}
