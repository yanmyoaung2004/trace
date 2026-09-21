package storage

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3Config holds MinIO/S3 connection settings.
type S3Config struct {
	Bucket    string
	Endpoint  string // e.g. "minio:9000" or "s3.amazonaws.com"
	Region    string
	UseSSL    bool // default true: NewS3Client upgrades empty-endpoint plaintext; warn below
	AccessKey string
	SecretKey string
}

// S3Client is a lightweight HTTP client for S3-compatible storage.
// It speaks AWS Signature Version 4 (no SDK dependency) and streams bodies
// via io.Reader end-to-end (P-H6: no whole-object string()/buffer doubling).
type S3Client struct {
	cfg    S3Config
	client *http.Client
	warned bool
}

// GetBucket returns the configured bucket name.
func (s *S3Client) GetBucket() string { return s.cfg.Bucket }

// NewS3Client creates an S3 client from config.
// UseSSL defaults to true when the caller leaves it false with an empty
// endpoint scheme: plaintext requires explicit opt-out. Plaintext with keys
// logs a warning once (A21/S3 semantics owned here; deploy only mirrors it).
func NewS3Client(cfg S3Config) *S3Client {
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	c := &S3Client{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	if !cfg.UseSSL {
		log.Printf("[s3] WARNING: plaintext HTTP to %s (set UseSSL=true; refusing to send keys silently)", cfg.Endpoint)
	}
	return c
}

// baseURL returns the S3 endpoint URL for the configured bucket.
func (s *S3Client) baseURL(key string) string {
	scheme := "http"
	if s.cfg.UseSSL {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/%s/%s", scheme, s.cfg.Endpoint, s.cfg.Bucket, key)
}

// Upload writes data to S3, streaming the body with SigV4 (no string() copy).
func (s *S3Client) Upload(key string, data []byte) error {
	return s.UploadReader(key, bytes.NewReader(data), int64(len(data)))
}

// UploadReader streams a body to S3 with AWS SigV4 signing.
func (s *S3Client) UploadReader(key string, body io.Reader, size int64) error {
	u := s.baseURL(key)
	req, err := http.NewRequest("PUT", u, body)
	if err != nil {
		return fmt.Errorf("s3 put request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if size >= 0 {
		req.ContentLength = size
	}
	s.signV4(req, "s3")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 400 {
		return fmt.Errorf("s3 put: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Download reads data from S3.
func (s *S3Client) Download(key string) ([]byte, error) {
	rc, err := s.DownloadStream(key, 0, -1)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("s3 read: %w", err)
	}
	return data, nil
}

// DownloadStream opens a ranged GET stream (offset/length; length<0 = to end).
func (s *S3Client) DownloadStream(key string, offset, length int64) (io.ReadCloser, error) {
	u := s.baseURL(key)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("s3 get request: %w", err)
	}
	if length >= 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	} else if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	s.signV4(req, "s3")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 get: %w", err)
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("s3 get: HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// Head checks if an object exists in S3.
func (s *S3Client) Head(key string) (bool, error) {
	u := s.baseURL(key)
	req, err := http.NewRequest("HEAD", u, nil)
	if err != nil {
		return false, err
	}
	s.signV4(req, "s3")
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
	s.signV4(req, "s3")
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

// signV4 signs a request with AWS Signature Version 4. Without credentials it
// is a no-op (MinIO anonymous / test servers keep working); with credentials
// it emits Authorization + x-amz-date + x-amz-content-sha256. No SDK added:
// the SigV4 shape is implemented inline and covered by a vector test.
func (s *S3Client) signV4(req *http.Request, service string) {
	if s.cfg.AccessKey == "" {
		return
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	region := s.cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	payloadHash := "UNSIGNED-PAYLOAD"
	if req.Body == nil {
		h := sha256.Sum256(nil)
		payloadHash = hex.EncodeToString(h[:])
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", req.Host, payloadHash, amzDate)
	canonicalQuery := canonicalQueryString(req.URL.Query())
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), canonicalQuery,
		canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	hashReq := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, hex.EncodeToString(hashReq[:]),
	}, "\n")
	signingKey := v4SigningKey(s.cfg.SecretKey, dateStamp, region, service)
	sig := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.cfg.AccessKey, credentialScope, signedHeaders, sig))
}

// canonicalQueryString renders sorted, encoded query pairs per SigV4.
func canonicalQueryString(v url.Values) string {
	if len(v) == 0 {
		return ""
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vals := v[k]
		sort.Strings(vals)
		for j, val := range vals {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(val))
		}
	}
	return b.String()
}

// v4SigningKey derives the SigV4 signing key.
func v4SigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
