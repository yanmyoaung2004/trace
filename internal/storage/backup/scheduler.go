package backup

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	"github.com/yanmyoaung2004/trace/internal/storage/snapshot"
)

// Config controls backup behavior.
type Config struct {
	Interval    time.Duration // how often to run backup
	BackupDir   string        // local directory for backups
	S3Bucket    string        // S3 bucket for remote backups
	S3Endpoint  string        // S3 endpoint
	S3AccessKey string
	S3SecretKey string
	S3UseSSL    bool
	MaxBackups  int // max local backups to retain (0 = unlimited)
	DataDir     string // TSE data directory
}

type Scheduler struct {
	cfg     Config
	s3      *storage.S3Client
	stopCh  chan struct{}
	doneCh  chan struct{}
	mu      sync.Mutex
	running bool
}

func NewScheduler(cfg Config) *Scheduler {
	s := &Scheduler{
		cfg:    cfg,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if cfg.S3Bucket != "" && cfg.S3Endpoint != "" {
		s.s3 = storage.NewS3Client(storage.S3Config{
			Bucket:    cfg.S3Bucket,
			Endpoint:  cfg.S3Endpoint,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			UseSSL:    cfg.S3UseSSL,
		})
	}
	return s
}

func (s *Scheduler) Start(ctx context.Context, f *flusher.Flusher, m *manifestpkg.Manifest) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	log.Printf("[backup] scheduler started (interval=%s, dir=%s)", s.cfg.Interval, s.cfg.BackupDir)

	go func() {
		defer close(s.doneCh)
		defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()

		// Run immediately on start
		s.runBackup(ctx, f, m)

		ticker := time.NewTicker(s.cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.runBackup(ctx, f, m)
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	close(s.stopCh)
	<-s.doneCh
}

func (s *Scheduler) runBackup(ctx context.Context, f *flusher.Flusher, m *manifestpkg.Manifest) {
	start := time.Now()
	ts := start.Format("20060102-150405")

	if s.cfg.BackupDir == "" {
		return
	}
	os.MkdirAll(s.cfg.BackupDir, 0700)

	// Local snapshot
	localPath := filepath.Join(s.cfg.BackupDir, fmt.Sprintf("tse-snapshot-%s.tar.gz", ts))
	if err := snapshot.Create(ctx, localPath, s.cfg.DataDir, f, m); err != nil {
		log.Printf("[backup] local snapshot failed: %v", err)
		return
	}
	log.Printf("[backup] local snapshot created: %s (%d bytes)", localPath, fileSize(localPath))

	// Upload to S3 if configured
	if s.s3 != nil {
		s3Key := fmt.Sprintf("backups/tse-snapshot-%s.tar.gz", ts)
		data, err := os.ReadFile(localPath)
		if err != nil {
			log.Printf("[backup] read for S3 upload: %v", err)
			return
		}
		if err := s.s3.Upload(s3Key, data); err != nil {
			log.Printf("[backup] S3 upload failed: %v", err)
			return
		}
		log.Printf("[backup] uploaded to s3://%s/%s", s.cfg.S3Bucket, s3Key)
	}

	// Rotate old backups
	if s.cfg.MaxBackups > 0 {
		s.rotateLocal()
	}

	log.Printf("[backup] completed in %s", time.Since(start))
}

func (s *Scheduler) rotateLocal() {
	entries, err := os.ReadDir(s.cfg.BackupDir)
	if err != nil {
		return
	}
	var backups []string
	for _, e := range entries {
		if !e.IsDir() {
			backups = append(backups, e.Name())
		}
	}
	for len(backups) > s.cfg.MaxBackups {
		oldest := backups[0]
		backups = backups[1:]
		os.Remove(filepath.Join(s.cfg.BackupDir, oldest))
		log.Printf("[backup] pruned old backup: %s", oldest)
	}
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
