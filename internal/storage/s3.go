package storage

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3Config holds MinIO/S3 connection settings.
type S3Config struct {
	Bucket   string
	Endpoint string // e.g. "minio:9000" or "s3.amazonaws.com"
	Region   string
	UseSSL   bool
	AccessKey string
	SecretKey string
}

// S3Client is a lightweight HTTP client for S3-compatible storage.
// No AWS SDK dependency — uses plain HTTP PUT/GET.
type S3Client struct {
	cfg    S3Config
	client *http.Client
}

// GetBucket returns the configured bucket name.
func (s *S3Client) GetBucket() string { return s.cfg.Bucket }

// NewS3Client creates an S3 client from config.
func NewS3Client(cfg S3Config) *S3Client {
	return &S3Client{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// baseURL returns the S3 endpoint URL for the configured bucket.
func (s *S3Client) baseURL(key string) string {
	scheme := "http"
	if s.cfg.UseSSL {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/%s", scheme, s.cfg.Endpoint, s.cfg.Bucket, key)
}

// Upload writes data to S3.
func (s *S3Client) Upload(key string, data []byte) error {
	u := s.baseURL(key)
	req, err := http.NewRequest("PUT", u, strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("s3 put request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if s.cfg.AccessKey != "" {
		req.SetBasicAuth(s.cfg.AccessKey, s.cfg.SecretKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("s3 put: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Download reads data from S3.
func (s *S3Client) Download(key string) ([]byte, error) {
	u := s.baseURL(key)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("s3 get request: %w", err)
	}
	if s.cfg.AccessKey != "" {
		req.SetBasicAuth(s.cfg.AccessKey, s.cfg.SecretKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("s3 get: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 read: %w", err)
	}
	return data, nil
}

// Head checks if an object exists in S3.
func (s *S3Client) Head(key string) (bool, error) {
	u := s.baseURL(key)
	req, err := http.NewRequest("HEAD", u, nil)
	if err != nil {
		return false, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// List returns all object keys with the given prefix.
func (s *S3Client) List(prefix string) ([]string, error) {
	u := s.baseURL("") + "?prefix=" + url.QueryEscape(prefix)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// Parse simple XML listing
	var keys []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "<Key>") {
			key := strings.TrimPrefix(line, "<Key>")
			key = strings.TrimSuffix(key, "</Key>")
			key = strings.TrimSpace(key)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

// IsS3Path returns true if the path starts with "s3://".
func IsS3Path(path string) bool {
	return strings.HasPrefix(path, "s3://")
}

// ParseS3Path splits "s3://bucket/key" into bucket and key.
func ParseS3Path(path string) (bucket, key string) {
	p := strings.TrimPrefix(path, "s3://")
	parts := strings.SplitN(p, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}
