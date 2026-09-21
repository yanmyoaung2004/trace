// Package updater implements the fail-closed agent self-update path.
//
// Trust model: the Check/Download endpoints are authenticated and the
// server is the distribution point. Every update refuses unless ALL of
// the following hold: HTTPS base URL, semver-newer version, non-empty
// SHA256 that matches the staged bytes, valid ed25519 signature over
// the raw SHA256 digest (the Check-response version<->sha<->signature
// binds the artifact; the download X-Trace-* headers are cross-check
// only), download URL confined to the configured server origin (no
// redirects off-origin), and a contained stage/verify/swap sequence
// with fsync before rename and rollback on swap failure. Unsigned,
// tampered, and downgraded updates are all refused; there is no
// warn-only mode here (CLI/installer warn-only paths are separate).
//
// Key provisioning: the ed25519 public key comes from local config via
// SetVerifyKey / SetVerifyKeyFromHex, with TRACE_UPDATE_VERIFY_KEY_HEX
// (32-byte hex) as the env fallback -- never from the network. When no
// key is provisioned every update is refused (fail-closed); when a key
// is provisioned an absent/invalid signature is refused.
//
// Stage layout: <dataDir>/updates/stage-<version>/binary (staged),
// swap target is the running executable, backup is <exe>.bak kept only
// for the duration of the swap and restored on failure.
package updater

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

	"golang.org/x/mod/semver"
)

// VerifyKey is the ed25519 public key updates are verified against.
// It is empty until provisioned via SetVerifyKey/SetVerifyKeyFromHex
// (local config or TRACE_UPDATE_VERIFY_KEY_HEX); verifySignatureHex
// lazily loads the env fallback. It is never taken from the network:
// when empty, ALL updates are refused (fail-closed) so an attacker who
// strips the signature cannot downgrade verification.
var verifyKey ed25519.PublicKey

// UpdateVerifyKeyHexEnv carries the hex-encoded ed25519 public key
// (32 bytes -> 64 hex chars) that updates are verified against.
const UpdateVerifyKeyHexEnv = "TRACE_UPDATE_VERIFY_KEY_HEX"

// SetVerifyKey provisions the offline update-signature public key.
// Passing an empty key clears it (verification then refuses everything).
func SetVerifyKey(key ed25519.PublicKey) { verifyKey = key }

// SetVerifyKeyFromHex parses a 32-byte hex public key and provisions it.
// An empty string clears the key (verification then refuses everything).
func SetVerifyKeyFromHex(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		verifyKey = nil
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("malformed update verify key: want 64 hex chars")
	}
	verifyKey = ed25519.PublicKey(append([]byte(nil), b...))
	return nil
}

// loadVerifyKeyFromEnv provisions the verify key from
// TRACE_UPDATE_VERIFY_KEY_HEX when SetVerifyKey has not already armed
// one. Malformed env refuses loudly (fail-closed); unset env leaves the
// key unconfigured and callers refuse with the no-key error.
func loadVerifyKeyFromEnv() error {
	if VerifyKeyConfigured() {
		return nil
	}
	raw := strings.TrimSpace(os.Getenv(UpdateVerifyKeyHexEnv))
	if raw == "" {
		return nil
	}
	return SetVerifyKeyFromHex(raw)
}

// VerifyKeyConfigured reports whether signature verification is armed.
func VerifyKeyConfigured() bool { return len(verifyKey) == ed25519.PublicKeySize }

// Updater polls the server update endpoint and applies verified updates.
type Updater struct {
	serverURL  string
	apiKey     string
	currentVer string
	dataDir    string
	client     *http.Client
}

// UpdateInfo describes one available update. Signature is base64 ed25519
// over the raw SHA256 digest bytes of the binary, as served in the Check
// JSON "signature" field (server-signed with TRACE_UPDATE_SIGNING_KEY).
// The download X-Trace-Signature header carries the same value for the
// installer path; here it is cross-check only, the Check response is the
// trust root. An empty signature refuses whenever a verify key is armed.
type UpdateInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	Signature   string `json:"signature,omitempty"`
	ReleaseDate string `json:"release_date"`
	Changelog   string `json:"changelog,omitempty"`
	Required    bool   `json:"required"`
}

// New builds an Updater. serverURL MUST be https (http allowed only for
// loopback hosts used in tests); other schemes are rejected at Check/Apply.
func New(serverURL, apiKey, currentVer, dataDir string) *Updater {
	return &Updater{
		serverURL:  serverURL,
		apiKey:     apiKey,
		currentVer: currentVer,
		dataDir:    dataDir,
		client: &http.Client{
			Timeout: 30 * time.Second,
			// No redirect following: download URLs must stay on the
			// configured server origin (checked explicitly). Following
			// redirects would let a compromised path bounce to attacker infra.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}
}

// SetAPIKey installs the server-issued key (post-enrollment) used to auth
// update check/download polls. Never used on the enroll path.
func (u *Updater) SetAPIKey(key string) { u.apiKey = key }

// requireHTTPSBase rejects non-https bases except loopback http (tests/dev).
func requireHTTPSBase(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme == "https" && u.Host != "" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing non-HTTPS update base %q (https required outside loopback)", raw)
}

func isLoopbackHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")
}

// canonicalVersion normalizes for semver compare: ensures leading "v".
func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// IsNewer reports whether info.Version is a valid semver strictly newer
// than current. Non-semver versions are never newer (fail-closed:
// lexicographic ">" once let "v9" beat "v10" and let junk pass).
func IsNewer(current, candidate string) bool {
	cur, cand := canonicalVersion(current), canonicalVersion(candidate)
	if !semver.IsValid(cur) || !semver.IsValid(cand) {
		return false
	}
	return semver.Compare(cand, cur) > 0
}

// Check queries the server for an available update. Returns (nil, nil)
// when up to date. Downgrades and same-version responses yield nil.
// The server wraps payloads in its {data,...} envelope; bare payloads
// are still accepted (tests, older servers).
func (u *Updater) Check(ctx context.Context) (*UpdateInfo, error) {
	if err := requireHTTPSBase(u.serverURL); err != nil {
		return nil, err
	}
	checkURL := fmt.Sprintf("%s/api/v1/edr/update/check?version=%s&platform=%s&arch=%s",
		strings.TrimSuffix(u.serverURL, "/"), url.QueryEscape(u.currentVer), runtime.GOOS, runtime.GOARCH)

	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
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

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check update: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var info UpdateInfo
	if err := json.Unmarshal(unwrapUpdatePayload(body), &info); err != nil {
		return nil, fmt.Errorf("parse update info: %w", err)
	}
	if info.Version == "" || info.Version == u.currentVer || !IsNewer(u.currentVer, info.Version) {
		return nil, nil
	}
	return &info, nil
}

// unwrapUpdatePayload extracts the inner "data" object from the server's
// JSON envelope, tolerating bare (pre-envelope) payloads.
func unwrapUpdatePayload(raw []byte) []byte {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Data) == 0 {
		return raw
	}
	return env.Data
}

// Apply stages, verifies, and swaps to info. Refuses fail-closed on:
// empty SHA256, missing verify key, signature absent/mismatch (_unsigned,
// tampered, and keyed-but-unsigned all refuse_), off-origin or non-HTTPS
// download URL, non-semver-newer version (downgrades refuse), path
// escape, fsync/rename errors. On swap failure the previous binary is
// restored. Verified bytes are chmod'd only after hash+signature pass.
func (u *Updater) Apply(ctx context.Context, info *UpdateInfo) error {
	if info == nil {
		return fmt.Errorf("refusing nil update")
	}
	if !IsNewer(u.currentVer, info.Version) {
		// Same-version is a no-op; downgrade is refused.
		if info.Version == u.currentVer || canonicalVersion(info.Version) == canonicalVersion(u.currentVer) {
			return nil
		}
		return fmt.Errorf("refusing downgrade to %q from %q", info.Version, u.currentVer)
	}
	if strings.TrimSpace(info.SHA256) == "" {
		return fmt.Errorf("refusing update %q: empty SHA256", info.Version)
	}
	if _, err := hex.DecodeString(strings.TrimSpace(info.SHA256)); err != nil {
		return fmt.Errorf("refusing update %q: malformed SHA256: %w", info.Version, err)
	}
	dlURL, err := u.confinedDownloadURL(info.DownloadURL)
	if err != nil {
		return err
	}

	stageDir, err := u.stageDir(info.Version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return fmt.Errorf("create stage dir: %w", err)
	}
	staged := filepath.Join(stageDir, "trace-agent"+binaryExt())

	if err := u.downloadBinary(ctx, dlURL, staged); err != nil {
		os.Remove(staged)
		return fmt.Errorf("download: %w", err)
	}
	// Stage -> verify -> swap. Any verify failure removes the stage.
	if err := verifyChecksum(staged, info.SHA256); err != nil {
		os.Remove(staged)
		return fmt.Errorf("checksum: %w", err)
	}
	if err := verifySignatureHex(info.SHA256, info.Signature); err != nil {
		os.Remove(staged)
		return fmt.Errorf("signature: %w", err)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		os.Remove(staged)
		return fmt.Errorf("chmod: %w", err)
	}

	currentExe, err := os.Executable()
	if err != nil {
		os.Remove(staged)
		return fmt.Errorf("get executable path: %w", err)
	}

	backupPath := currentExe + ".bak"
	os.Remove(backupPath)

	if err := os.Rename(currentExe, backupPath); err != nil {
		os.Remove(staged)
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := os.Rename(staged, currentExe); err != nil {
		_ = os.Rename(backupPath, currentExe) // rollback
		return fmt.Errorf("swap binary failed, restored backup: %w", err)
	}

	os.Remove(backupPath)
	os.Remove(staged)
	return nil
}

// confinedDownloadURL requires the download URL to be https (or loopback
// http) on the same origin as the configured server. The server selects
// the asset (?os=&arch= flow); clients never accept server-sent absolute
// URLs pointing elsewhere — that was the MITM/off-origin hole.
func (u *Updater) confinedDownloadURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("refusing update: empty download URL")
	}
	base, err := url.Parse(u.serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}
	dl, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("refusing update: bad download URL: %w", err)
	}
	if !dl.IsAbs() {
		// Relative: resolve against the server base (server-picked asset).
		dl = base.ResolveReference(dl)
	}
	if !equalOrigin(base, dl) {
		return "", fmt.Errorf("refusing update: download origin %q not on server origin %q",
			dl.Scheme+"://"+dl.Host, base.Scheme+"://"+base.Host)
	}
	if dl.Scheme == "https" && dl.Host != "" {
		return dl.String(), nil
	}
	if dl.Scheme == "http" && isLoopbackHost(dl.Hostname()) {
		return dl.String(), nil
	}
	return "", fmt.Errorf("refusing update: download URL %q not HTTPS", dl.Redacted())
}

func equalOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// stageDir confines staging under dataDir/updates/stage-<version>.
// Version is sanitized so ".." / separators cannot escape (filepath.Rel
// check + symlink refusal at create time).
func (u *Updater) stageDir(version string) (string, error) {
	safe := strings.TrimSpace(version)
	if safe == "" || safe == "." || strings.ContainsAny(safe, `/\`) || strings.Contains(safe, "..") {
		return "", fmt.Errorf("refusing update: unsafe version %q", version)
	}
	root := filepath.Join(u.dataDir, "updates")
	rel, err := filepath.Rel(root, filepath.Join(root, "stage-"+safe))
	if err != nil || rel != "stage-"+safe {
		return "", fmt.Errorf("refusing update: version escapes stage dir: %q", version)
	}
	// Refuse a symlinked stage root (TOCTOU containment).
	if fi, err := os.Lstat(root); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing update: stage root is a symlink")
	}
	return filepath.Join(root, rel), nil
}

func (u *Updater) downloadBinary(ctx context.Context, rawURL, dest string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
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

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
		return fmt.Errorf("refusing redirect to %q (downloads stay on server origin)", resp.Header.Get("Location"))
	}
	// The server also returns the binary hash/signature as X-Trace-SHA256 /
	// X-Trace-Signature alongside the bytes, but this path deliberately
	// does NOT trust them: Apply verifies the staged file against the
	// signed Check response (the trust root), so a byte-swap between check
	// and download cannot slip through. Absent headers are tolerated here.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	// Symlink refusal: Lstat before create (TOCTOU window is bounded by the
	// 0700 stage dir owned by the agent user; Windows has no O_NOFOLLOW).
	if fi, err := os.Lstat(dest); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing download: dest is a symlink")
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	written, err := io.Copy(f, io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if written < 1024*1024 {
		return fmt.Errorf("binary suspiciously small: %d bytes", written)
	}

	// fsync file then containing dir before rename (durability: a crash
	// between write and swap must not leave a half binary).
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync staged binary: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}
	if d, err := os.Open(filepath.Dir(dest)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// verifyChecksum requires expected to be non-empty hex of the file's
// SHA256. Empty expected refuses (this was the fail-open hole).
func verifyChecksum(file, expected string) error {
	expected = strings.TrimSpace(strings.ToLower(expected))
	if expected == "" {
		return fmt.Errorf("refusing: empty expected SHA256")
	}
	want, err := hex.DecodeString(expected)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("refusing: malformed expected SHA256")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := h.Sum(nil)
	// Constant-time compare would need subtle; mismatch content is not
	// secret, but avoid prefix-truncated messages that hid mismatches.
	if hex.EncodeToString(got) != expected {
		return fmt.Errorf("checksum mismatch: got %s, expected %s",
			hex.EncodeToString(got), expected)
	}
	return nil
}

// verifySignatureHex verifies base64 ed25519 over the raw SHA256 digest.
// Fail-closed throughout: no verify key (including via
// TRACE_UPDATE_VERIFY_KEY_HEX) refuses everything; key armed but
// signature absent/malformed/invalid refuses; tampered bytes refuse via
// the staged checksum gate before this runs. Unsigned, tampered, and
// downgraded (non-newer, see Apply/IsNewer) updates never reach the swap.
func verifySignatureHex(shaHex, sigB64 string) error {
	if err := loadVerifyKeyFromEnv(); err != nil {
		return fmt.Errorf("refusing: %w", err)
	}
	if !VerifyKeyConfigured() {
		return fmt.Errorf("refusing: no update verify key configured (provision offline pubkey)")
	}
	if strings.TrimSpace(sigB64) == "" {
		return fmt.Errorf("refusing: update lacks signature")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(shaHex))
	if err != nil || len(raw) != sha256.Size {
		return fmt.Errorf("refusing: malformed SHA256 for signature check")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("refusing: malformed signature")
	}
	if !ed25519.Verify(verifyKey, raw, sig) {
		return fmt.Errorf("refusing: signature verification failed")
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
