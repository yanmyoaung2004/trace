package taskqueue

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/db"
)

// Queue is a SQLite-backed task queue with leases and a dead-letter state.
type Queue struct {
	db *db.DB
}

// New creates a Queue over an existing *db.DB connection.
func New(database *db.DB) *Queue {
	return &Queue{db: database}
}

// Task states: pending -> running -> done | failed. Failed tasks with
// attempts left return to pending with a not-before lease; exhausted tasks
// move to dead (DLQ) and are never re-claimed.
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
	StatusDead    = "dead"
)

// Claim errors are typed so callers can distinguish empty from failure.
type ClaimError struct {
	Op  string
	Err error
}

func (e *ClaimError) Error() string { return e.Op + ": " + e.Err.Error() }
func (e *ClaimError) Unwrap() error { return e.Err }

type Task struct {
	ID               string
	InvestigationID  string
	Agent            string
	Action           string
	Payload          map[string]any
	Status           string
	Result           map[string]any
	Error            string
	Attempts         int
	MaxAttempts      int
	LeaseExpiresAt   string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
func (q *Queue) Enqueue(ctx context.Context, investigationID, agent, action string, payload map[string]any) (*Task, error) {
	return q.EnqueueWithAttempts(ctx, investigationID, agent, action, payload, 5)
}

func (q *Queue) EnqueueWithAttempts(ctx context.Context, investigationID, agent, action string, payload map[string]any, maxAttempts int) (*Task, error) {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	id := uuid.New().String()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, &ClaimError{Op: "marshal payload", Err: err}
	}

	q.ensureTaskCols(ctx)
	_, err = q.db.ExecContext(ctx,
		`INSERT INTO tasks (id, investigation_id, agent, action, payload, status, attempts, max_attempts)
		 VALUES (?, ?, ?, ?, ?, 'pending', 0, ?)`,
		id, investigationID, agent, action, string(payloadJSON), maxAttempts)
	if err != nil {
		return nil, &ClaimError{Op: "insert task", Err: err}
	}

	return &Task{ID: id, InvestigationID: investigationID, Agent: agent, Action: action, Status: StatusPending, MaxAttempts: maxAttempts}, nil
}

// Claim atomically claims one pending task. Single UPDATE ... WHERE
// status='pending' ... RETURNING-equivalent: the UPDATE only succeeds when
// the row is still pending and its lease expired, so two workers cannot
// double-claim the same task.
func (q *Queue) Claim(ctx context.Context) (*Task, error) {
	q.ensureTaskCols(ctx)
	// Atomic single-UPDATE claim: exactly one row flips to running, and we
	// read back the same row by lease timestamp (no second-writer race can
	// interleave between the UPDATE and the SELECT on a single node; the
	// lease value is unique per claim).
	leaseID := uuid.New().String()
	res, err := q.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'running', attempts = COALESCE(attempts,0)+1, lease_expires_at = ?, updated_at = datetime('now')
		 WHERE id = (SELECT id FROM tasks WHERE status = 'pending' AND (lease_expires_at IS NULL OR lease_expires_at <= datetime('now')) AND COALESCE(attempts,0) < COALESCE(max_attempts,5) ORDER BY rowid ASC LIMIT 1)`, leaseID)
	if err != nil {
		return nil, &ClaimError{Op: "claim task", Err: err}
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, nil
	}
	var (
		id, invID, agentName, action, payloadStr, status string
		createdAt, updatedAt                            string
		attempts, maxAttempts                           sql.NullInt64
		lease                                           sql.NullString
	)
	if err := q.db.QueryRowContext(ctx,
		`SELECT id, investigation_id, agent, action, payload, status, created_at, updated_at, attempts, max_attempts, lease_expires_at
		 FROM tasks WHERE lease_expires_at = ?`, leaseID).Scan(
		&id, &invID, &agentName, &action, &payloadStr, &status, &createdAt, &updatedAt, &attempts, &maxAttempts, &lease); err != nil {
		return nil, &ClaimError{Op: "read claimed task", Err: err}
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
		return nil, &ClaimError{Op: "decode payload", Err: err}
	}

	task := &Task{
		ID:              id,
		InvestigationID: invID,
		Agent:           agentName,
		Action:          action,
		Payload:         payload,
		Status:          StatusRunning,
	}
	if attempts.Valid {
		task.Attempts = int(attempts.Int64)
	}
	if maxAttempts.Valid {
		task.MaxAttempts = int(maxAttempts.Int64)
	}
	if lease.Valid {
		task.LeaseExpiresAt = lease.String
	}
	return task, nil
}

func (q *Queue) Complete(ctx context.Context, taskID string, result map[string]any) error {
	resultJSON, _ := json.Marshal(result)
	_, err := q.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'done', result = ?, updated_at = datetime('now') WHERE id = ? AND status = 'running'`,
		string(resultJSON), taskID)
	return err
}

// Fail records an attempt. Attempts left: back to pending with a lease so a
// poison task cannot hot-loop. Exhausted: to dead (DLQ).
func (q *Queue) Fail(ctx context.Context, taskID string, errMsg string) error {
	q.ensureTaskCols(ctx)
	_, err := q.db.ExecContext(ctx,
		`UPDATE tasks SET error = ?, updated_at = datetime('now'),
			status = CASE WHEN COALESCE(attempts,0) >= COALESCE(max_attempts,5) THEN 'dead' ELSE 'pending' END,
			lease_expires_at = CASE WHEN COALESCE(attempts,0) >= COALESCE(max_attempts,5) THEN lease_expires_at ELSE datetime('now', '+1 minute') END
		 WHERE id = ?`, errMsg, taskID)
	return err
}

// RequeueExpired returns running tasks whose lease lapsed to pending.
func (q *Queue) RequeueExpired(ctx context.Context) (int64, error) {
	q.ensureTaskCols(ctx)
	res, err := q.db.ExecContext(ctx,
		`UPDATE tasks SET status = 'pending', updated_at = datetime('now') WHERE status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at <= datetime('now')`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ensureTaskCols adds lease/attempt columns on old databases (additive).
func (q *Queue) ensureTaskCols(ctx context.Context) {
	for _, ddl := range []string{
		`ALTER TABLE tasks ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tasks ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 5`,
		`ALTER TABLE tasks ADD COLUMN lease_expires_at TEXT`,
		`ALTER TABLE tasks ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
	} {
		_, _ = q.db.ExecContext(ctx, ddl)
	}
}
