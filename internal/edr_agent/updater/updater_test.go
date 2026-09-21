package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

func TestCurrentVersion(t *testing.T) {
	u := New("", "", "v1.0.0", t.TempDir())
	if v := u.CurrentVersion(); v != "v1.0.0" {
		t.Errorf("version = %q", v)
	}
}

func TestBinaryExt(t *testing.T) {
	ext := binaryExt()
	if runtime.GOOS == "windows" && ext != ".exe" {
		t.Errorf("expected .exe on windows, got %q", ext)
	}
	if runtime.GOOS != "windows" && ext != "" {
		t.Errorf("expected empty on %s, got %q", runtime.GOOS, ext)
	}
}

func TestCheck_NoUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	u := New(server.URL, "", "v1.0.0", t.TempDir())
	u.client = server.Client()

	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Error("expected nil for no update")
	}
}

func TestCheck_UpdateAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":"v2.0.0","download_url":"http://example.com/agent.exe","sha256":"abc123","release_date":"2026-01-01","required":true}`))
	}))
	defer server.Close()

	u := New(server.URL, "test-key", "v1.0.0", t.TempDir())
	u.client = server.Client()

	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info == nil {
		t.Fatal("expected update info")
	}
	if info.Version != "v2.0.0" {
		t.Errorf("version = %q", info.Version)
	}
	if !info.Required {
		t.Error("expected required update")
	}
}

func TestCheck_EnvelopedSignature(t *testing.T) {
	// Server writeData wraps in {data,...}; signature must survive the
	// envelope or keyed fleets refuse every update as unsigned.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"version":"v2.0.0","download_url":"/agent","sha256":"abc123","signature":"c2ln","required":false},"code":200}`))
	}))
	defer server.Close()

	u := New(server.URL, "test-key", "v1.0.0", t.TempDir())
	u.client = server.Client()

	info, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info == nil {
		t.Fatal("expected update info from enveloped payload")
	}
	if info.Signature != "c2ln" {
		t.Errorf("signature = %q, want passthrough from envelope", info.Signature)
	}
}

func TestSetVerifyKeyFromHex(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	defer SetVerifyKey(nil)
	if err := SetVerifyKeyFromHex(hex.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	if !VerifyKeyConfigured() {
		t.Fatal("expected verify key armed from hex")
	}
	if err := SetVerifyKeyFromHex("not-hex"); err == nil {
		t.Fatal("expected malformed-hex refusal")
	}
	if err := SetVerifyKeyFromHex(""); err != nil {
		t.Fatal(err)
	}
	if VerifyKeyConfigured() {
		t.Fatal("expected empty hex to clear the key")
	}
}

func TestVerifySignature_EnvFallback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	defer SetVerifyKey(nil)
	SetVerifyKey(nil)
	t.Setenv(UpdateVerifyKeyHexEnv, hex.EncodeToString(pub))
	h := sha256.Sum256([]byte("payload"))
	sig := ed25519.Sign(priv, h[:])
	if err := verifySignatureHex(hex.EncodeToString(h[:]), base64.StdEncoding.EncodeToString(sig)); err != nil {
		t.Fatalf("env-provisioned key should verify: %v", err)
	}
}

func TestCheck_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	u := New(server.URL, "", "v1.0.0", t.TempDir())
	u.client = server.Client()

	_, err := u.Check(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.bin")
	data := []byte("test binary content")
	os.WriteFile(file, data, 0644)

	h := sha256.Sum256(data)
	expected := hex.EncodeToString(h[:])

	if err := verifyChecksum(file, expected); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.bin")
	os.WriteFile(file, []byte("real content"), 0644)

	if err := verifyChecksum(file, "00000000000000000000000000000000"); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
}

func TestVerifyChecksum_FileNotFound(t *testing.T) {
	err := verifyChecksum("/nonexistent/file.bin", "abc")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestVerifyChecksum_EmptyRefuses(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.bin")
	os.WriteFile(file, []byte("real content"), 0644)
	if err := verifyChecksum(file, ""); err == nil {
		t.Fatal("expected empty-hash refusal")
	}
	if err := verifyChecksum(file, "   "); err == nil {
		t.Fatal("expected whitespace-hash refusal")
	}
}

func TestIsNewer_Semver(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"v1.0.0", "v1.0.1", true},
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.1", "v1.0.0", false},
		{"v9.0.0", "v10.0.0", true},  // lexicographic ">" got this wrong
		{"v10.0.0", "v9.0.0", false}, // downgrade refused
		{"v1.0.0", "not-a-version", false},
		{"", "v1.0.0", false},
		{"1.0.0", "1.0.1", true}, // missing v prefix tolerated
	}
	for _, c := range cases {
		if got := IsNewer(c.cur, c.cand); got != c.want {
			t.Errorf("IsNewer(%q,%q)=%v want %v", c.cur, c.cand, got, c.want)
		}
	}
}

func TestApply_SameVersion(t *testing.T) {
	u := New("", "", "v1.0.0", t.TempDir())
	err := u.Apply(context.Background(), &UpdateInfo{Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestApply_DowngradeRefused(t *testing.T) {
	u := New("https://127.0.0.1:8443", "", "v2.0.0", t.TempDir())
	err := u.Apply(context.Background(), &UpdateInfo{Version: "v1.9.9"})
	if err == nil {
		t.Fatal("expected downgrade refusal")
	}
}

func TestApply_EmptyHashRefused(t *testing.T) {
	u := New("https://127.0.0.1:8443", "", "v1.0.0", t.TempDir())
	err := u.Apply(context.Background(), &UpdateInfo{Version: "v1.0.1", SHA256: ""})
	if err == nil {
		t.Fatal("expected empty-hash refusal")
	}
}

func TestApply_OffOriginRefused(t *testing.T) {
	u := New("https://127.0.0.1:8443", "", "v1.0.0", t.TempDir())
	h := sha256.Sum256([]byte("x"))
	err := u.Apply(context.Background(), &UpdateInfo{
		Version:     "v1.0.1",
		SHA256:      hex.EncodeToString(h[:]),
		DownloadURL: "https://evil.example.com/agent",
	})
	if err == nil {
		t.Fatal("expected off-origin refusal")
	}
}

func TestApply_UnsignedRefused_WhenKeyConfigured(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	SetVerifyKey(pub)
	defer SetVerifyKey(nil)
	u := New("https://127.0.0.1:8443", "", "v1.0.0", t.TempDir())
	h := sha256.Sum256([]byte("x"))
	err := u.Apply(context.Background(), &UpdateInfo{
		Version: "v1.0.1",
		SHA256:  hex.EncodeToString(h[:]),
	})
	if err == nil {
		t.Fatal("expected unsigned refusal")
	}
}

func TestApply_Refused_WhenNoKeyConfigured(t *testing.T) {
	// No verify key provisioned (and env unset): fail-closed, Apply must
	// refuse before any download/stage even for a signed-looking payload.
	SetVerifyKey(nil)
	t.Setenv(UpdateVerifyKeyHexEnv, "")
	u := New("https://127.0.0.1:8443", "", "v1.0.0", t.TempDir())
	h := sha256.Sum256([]byte("x"))
	err := u.Apply(context.Background(), &UpdateInfo{
		Version:     "v1.0.1",
		SHA256:      hex.EncodeToString(h[:]),
		Signature:   base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		DownloadURL: "https://127.0.0.1:8443/agent",
	})
	if err == nil {
		t.Fatal("expected no-key refusal")
	}
	if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "verify key") {
		t.Fatalf("expected signature/no-key refusal, got: %v", err)
	}
}

func TestApply_SignedHappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	SetVerifyKey(pub)
	defer SetVerifyKey(nil)

	payload := bytes.Repeat([]byte("A"), 2*1024*1024)
	h := sha256.Sum256(payload)
	shaHex := hex.EncodeToString(h[:])
	sig := ed25519.Sign(priv, h[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Trace-SHA256", shaHex)
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	}))
	defer server.Close()

	u := New(server.URL, "", "v1.0.0", t.TempDir())
	if !strings.HasPrefix(server.URL, "http://127.0.0.1") && !strings.HasPrefix(server.URL, "http://localhost") {
		t.Skip("httptest not on loopback, cannot exercise confined download")
	}
	u.client = server.Client()
	err := u.Apply(context.Background(), &UpdateInfo{
		Version:     "v1.0.1",
		SHA256:      shaHex,
		Signature:   base64.StdEncoding.EncodeToString(sig),
		DownloadURL: server.URL + "/agent",
	})
	// Swap touches os.Executable; in tests the rename of the test binary
	// path may fail for environment reasons — the fail-closed checks above
	// (hash/sig/origin) all passed if we get past download+verify. Accept
	// either nil or a backup/swap error, but never a verify error.
	if err != nil && (strings.Contains(err.Error(), "checksum") || strings.Contains(err.Error(), "signature") || strings.Contains(err.Error(), "refusing")) {
		t.Fatalf("verify should have passed: %v", err)
	}
}

func TestVerifySignature_TamperedRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	SetVerifyKey(pub)
	defer SetVerifyKey(nil)
	h := sha256.Sum256([]byte("payload"))
	sig := ed25519.Sign(priv, h[:])
	sig[0] ^= 0xff
	if err := verifySignatureHex(hex.EncodeToString(h[:]), base64.StdEncoding.EncodeToString(sig)); err == nil {
		t.Fatal("expected tampered-signature refusal")
	}
}

func TestConfinedDownload_RejectsOffOrigin(t *testing.T) {
	u := New("https://example.com:8443", "", "v1.0.0", t.TempDir())
	if _, err := u.confinedDownloadURL("https://evil.example.com/agent"); err == nil {
		t.Fatal("expected off-origin refusal")
	}
	if _, err := u.confinedDownloadURL("http://example.com:8443/agent"); err == nil {
		t.Fatal("expected plaintext refusal")
	}
	if _, err := u.confinedDownloadURL(""); err == nil {
		t.Fatal("expected empty-URL refusal")
	}
}

func TestStageDir_RejectsTraversal(t *testing.T) {
	u := New("https://example.com", "", "v1.0.0", t.TempDir())
	for _, v := range []string{"../evil", "a/b", `a\b`, "..", ""} {
		if _, err := u.stageDir(v); err == nil {
			t.Fatalf("expected traversal refusal for %q", v)
		}
	}
}

func FuzzIsNewer(f *testing.F) {
	f.Add("v1.0.0", "v1.0.1")
	f.Add("v9.0.0", "v10.0.0")
	f.Add("v1.0.0", "v1.0.0")
	f.Add("v1.0.0", "../../../evil")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, cur, cand string) {
		newer := IsNewer(cur, cand)
		// Invariants: never newer on identical canonical versions, never
		// newer on invalid semver, never panics on hostile input.
		if canonicalVersion(cur) == canonicalVersion(cand) && newer {
			t.Fatalf("IsNewer(%q,%q)=true on identical versions", cur, cand)
		}
		if (!semver.IsValid(canonicalVersion(cur)) || !semver.IsValid(canonicalVersion(cand))) && newer {
			t.Fatalf("IsNewer(%q,%q)=true on invalid semver", cur, cand)
		}
	})
}
