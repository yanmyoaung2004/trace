package gc

import (
	"context"
	"log"
	"time"

	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
)

// TTLPolicy defines retention for different compliance frameworks.
type TTLPolicy struct {
	Framework string
	Duration  time.Duration
}

// DefaultTTLPolicies returns sensible defaults for compliance frameworks.
var DefaultTTLPolicies = []TTLPolicy{
	{Framework: "default", Duration: 365 * 24 * time.Hour},
	{Framework: "pci_dss", Duration: 365 * 24 * time.Hour},
	{Framework: "hipaa", Duration: 6 * 365 * 24 * time.Hour},
	{Framework: "gdpr", Duration: 365 * 24 * time.Hour},
}

// TTLManager applies time-to-live policies to Parquet files.
type TTLManager struct {
	manifest  *manifestpkg.Manifest
	policies  []TTLPolicy
	interval  time.Duration
}

// NewTTLManager creates a TTL manager with the given retention policies.
func NewTTLManager(m *manifestpkg.Manifest, policies []TTLPolicy, interval time.Duration) *TTLManager {
	if len(policies) == 0 {
		policies = DefaultTTLPolicies
	}
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &TTLManager{
		manifest: m,
		policies: policies,
		interval: interval,
	}
}

// Run starts the TTL loop. Blocks until context is cancelled.
func (t *TTLManager) Run(ctx context.Context) error {
	log.Printf("[ttl] started (interval=%v)", t.interval)

	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			t.applyOnce(ctx)
		}
	}
}

// applyOnce checks all committed files against TTL policies and marks
// expired ones with status='expired'.
func (t *TTLManager) applyOnce(ctx context.Context) {
	now := time.Now()
	for _, policy := range t.policies {
		cutoff := now.Add(-policy.Duration).UnixMicro()
		files, err := t.manifest.FilesFor(ctx, "", 0, cutoff, "committed")
		if err != nil {
			log.Printf("[ttl] list files: %v", err)
			continue
		}

		for _, f := range files {
			if err := t.manifest.UpdateFileStatus(ctx, f.FileID, "expired"); err != nil {
				log.Printf("[ttl] expire %s: %v", f.FileID, err)
			}
		}

		if len(files) > 0 {
			log.Printf("[ttl] expired %d files (%s: %v)", len(files), policy.Framework, policy.Duration)
		}
	}
}
