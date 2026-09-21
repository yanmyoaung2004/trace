package sqlite

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// Checkpointer manages WAL checkpoints on the hot store SQLite database.
// It runs passive checkpoints periodically and escalates to truncate
// checkpoints only during idle periods.
type Checkpointer struct {
	db          *sql.DB
	interval    time.Duration
	passiveBusy int
}

// NewCheckpointer creates a checkpointer that runs passive checkpoints
// on the given writer database connection at the specified interval.
func NewCheckpointer(db *sql.DB, interval time.Duration) *Checkpointer {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &Checkpointer{db: db, interval: interval}
}

// Run starts the checkpoint loop. It blocks until the context is cancelled.
func (c *Checkpointer) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.checkpoint()
		}
	}
}

// checkpoint attempts a passive WAL checkpoint. If passive checkpoints keep
// reporting busy while the WAL grows, the next idle tick escalates to
// TRUNCATE. WAL size is exported via the metrics package by the caller (R2).
func (c *Checkpointer) checkpoint() {
	// Passive checkpoint — succeeds if no readers are active
	// Returns (busy, log, checkpointed)
	var busy, walPages, checkpointed int
	err := c.db.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &walPages, &checkpointed)
	if err != nil {
		log.Printf("[tse] checkpoint error: %v", err)
		return
	}
	if busy != 0 {
		c.passiveBusy++
	} else {
		c.passiveBusy = 0
	}
	// Escalate to TRUNCATE only after repeated busy passives (idle window):
	// avoids blocking readers on every tick while still bounding WAL growth.
	if c.passiveBusy >= 6 && walPages > 1000 {
		var b, w, ckpt int
		if err := c.db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&b, &w, &ckpt); err != nil {
			log.Printf("[tse] checkpoint truncate error: %v", err)
		} else if b == 0 {
			c.passiveBusy = 0
		}
	}
}

// ForceCheckpoint immediately truncates the WAL.
func (c *Checkpointer) ForceCheckpoint(ctx context.Context) error {
	var busy, walPages, checkpointed int
	err := c.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &walPages, &checkpointed)
	return err
}
