package backup

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	// Upload to S3 if configured: stream from disk (W4: no whole-file
	// ReadFile buffering — a snapshot can be gigabytes).
	if s.s3 != nil {
		s3Key := fmt.Sprintf("backups/tse-snapshot-%s.tar.gz", ts)
		if err := s.uploadToS3(localPath, s3Key); err != nil {
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

// SnapshotPrefix is the only filename prefix the rotator may delete. Anything
// else in the backup dir (user files, db dumps, stray temps, in-flight .tmp-*
// files) is never removed by rotation.
const SnapshotPrefix = "tse-snapshot-"

// SnapshotSuffix bounds rotation to finished gzip tarballs.
const SnapshotSuffix = ".tar.gz"

func (s *Scheduler) uploadToS3(localPath, s3Key string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open for S3 upload: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat for S3 upload: %w", err)
	}
	return s.s3.UploadReader(s3Key, f, fi.Size())
}

func (s *Scheduler) rotateLocal() {
	entries, err := os.ReadDir(s.cfg.BackupDir)
	if err != nil {
		return
	}
	var backups []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		// Filter: only finished snapshots are rotation-eligible.
		if !strings.HasPrefix(name, SnapshotPrefix) || !strings.HasSuffix(name, SnapshotSuffix) {
			continue
		}
		backups = append(backups, name)
	}
	sort.Strings(backups) // timestamped names sort oldest-first
	for len(backups) > s.cfg.MaxBackups {
		oldest := backups[0]
		backups = backups[1:]
		if err := os.Remove(filepath.Join(s.cfg.BackupDir, oldest)); err != nil {
			log.Printf("[backup] prune %s: %v (keeping remainder)", oldest, err)
			break
		}
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
