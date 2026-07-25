package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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

func TestApply_SameVersion(t *testing.T) {
	u := New("", "", "v1.0.0", t.TempDir())
	err := u.Apply(context.Background(), &UpdateInfo{Version: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
}
