package storage

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseS3Path(t *testing.T) {
	tests := []struct {
		path         string
		wantBucket   string
		wantKey      string
	}{
		{"s3://bucket/key.parquet", "bucket", "key.parquet"},
		{"s3://bucket/a/b/c.parquet", "bucket", "a/b/c.parquet"},
	}
	for _, tt := range tests {
		bucket, key := ParseS3Path(tt.path)
		if bucket != tt.wantBucket {
			t.Errorf("ParseS3Path(%q) bucket = %q, want %q", tt.path, bucket, tt.wantBucket)
		}
		if key != tt.wantKey {
			t.Errorf("ParseS3Path(%q) key = %q, want %q", tt.path, key, tt.wantKey)
		}
	}
}

func TestIsS3Path(t *testing.T) {
	if !IsS3Path("s3://bucket/key") {
		t.Error("expected true for s3:// path")
	}
	if IsS3Path("/local/path/file.parquet") {
		t.Error("expected false for local path")
	}
	if IsS3Path("") {
		t.Error("expected false for empty path")
	}
}

func TestS3Client_UploadDownload(t *testing.T) {
	store := make(map[string][]byte)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		switch r.Method {
		case "PUT":
			store[key], _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case "GET":
			if data, ok := store[key]; ok {
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		case "HEAD":
			if _, ok := store[key]; ok {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	defer server.Close()

	cfg := S3Config{
		Bucket:   "test-bucket",
		Endpoint: strings.TrimPrefix(server.URL, "http://"),
	}
	client := NewS3Client(cfg)
	client.client = server.Client()

	// Upload
	testData := []byte("test parquet data")
	if err := client.Upload("events/test.parquet", testData); err != nil {
		t.Fatal(err)
	}

	// Download
	downloaded, err := client.Download("events/test.parquet")
	if err != nil {
		t.Fatal(err)
	}
	if string(downloaded) != string(testData) {
		t.Errorf("data mismatch: got %q, want %q", string(downloaded), string(testData))
	}

	// Head
	exists, err := client.Head("events/test.parquet")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("expected object to exist")
	}

	// Head (not found)
	exists, err = client.Head("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("expected nonexistent object")
	}
}

func TestS3Client_UploadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := S3Config{
		Bucket:   "test",
		Endpoint: strings.TrimPrefix(server.URL, "http://"),
	}
	client := NewS3Client(cfg)
	client.client = server.Client()

	err := client.Upload("key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestS3Client_GetBucket(t *testing.T) {
	cfg := S3Config{Bucket: "my-bucket"}
	client := NewS3Client(cfg)
	if client.GetBucket() != "my-bucket" {
		t.Errorf("bucket = %q", client.GetBucket())
	}
}

func TestS3BaseURL(t *testing.T) {
	cfg := S3Config{Bucket: "b", Endpoint: "minio:9000"}
	client := NewS3Client(cfg)
	expected := "http://minio:9000/b/test.parquet"
	got := client.baseURL("test.parquet")
	if got != expected {
		t.Errorf("baseURL = %q, want %q", got, expected)
	}
}
