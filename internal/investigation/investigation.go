package investigation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/db"
)

type Investigation struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	Intent     string   `json:"intent"`
	Playbook   string   `json:"playbook,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
}

type Manager struct {
	db *db.DB
}

func NewManager(database *db.DB) *Manager {
	return &Manager{db: database}
}

func (m *Manager) Create(ctx context.Context, intent, playbook string) (*Investigation, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	inv := &Investigation{
		ID:        uuid.New().String(),
		Status:    "pending",
		Intent:    intent,
		Playbook:  playbook,
		CreatedAt: now,
		UpdatedAt: now,
	}

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO investigations (id, status, intent, playbook) VALUES (?, ?, ?, ?)`,
		inv.ID, inv.Status, inv.Intent, inv.Playbook)
	if err != nil {
		return nil, fmt.Errorf("create investigation: %w", err)
	}

	return inv, nil
}

func (m *Manager) Get(ctx context.Context, id string) (*Investigation, error) {
	var inv Investigation
	err := m.db.QueryRowContext(ctx,
		`SELECT id, status, intent, playbook, confidence, created_at, updated_at FROM investigations WHERE id = ?`, id).
		Scan(&inv.ID, &inv.Status, &inv.Intent, &inv.Playbook, &inv.Confidence, &inv.CreatedAt, &inv.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get investigation: %w", err)
	}
	return &inv, nil
}

func (m *Manager) GetByPrefix(ctx context.Context, prefix string) (*Investigation, error) {
	// Traversal-safe: prefix is matched as a literal (escape LIKE wildcards),
	// allowlisted to hex/UUID chars, and matched from the ID start only.
	clean := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-' {
			return r
		}
		return -1
	}, prefix)
	if clean == "" || len(clean) > 64 {
		return nil, fmt.Errorf("invalid id prefix")
	}
	esc := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(clean, `\`, `\\`), `%`, `\%`), `_`, `\_`)
	var inv Investigation
	err := m.db.QueryRowContext(ctx,
		`SELECT id, status, intent, playbook, confidence, created_at, updated_at FROM investigations WHERE id LIKE ? ESCAPE '\' ORDER BY created_at DESC LIMIT 1`, esc+"%").
		Scan(&inv.ID, &inv.Status, &inv.Intent, &inv.Playbook, &inv.Confidence, &inv.CreatedAt, &inv.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get by prefix: %w", err)
	}
	return &inv, nil
}

func (m *Manager) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE investigations SET status = ?, updated_at = datetime('now') WHERE id = ?`, status, id)
	return err
}

func (m *Manager) ListPendingApprovals(ctx context.Context) ([]Investigation, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, status, intent, playbook, confidence, created_at, updated_at
		 FROM investigations WHERE status = 'waiting_approval' ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("query pending approvals: %w", err)
	}
	defer rows.Close()

	var out []Investigation
	for rows.Next() {
		var inv Investigation
		if err := rows.Scan(&inv.ID, &inv.Status, &inv.Intent, &inv.Playbook, &inv.Confidence, &inv.CreatedAt, &inv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, inv)
	}
	return out, nil
}

func (m *Manager) ListRecent(ctx context.Context, limit int) ([]Investigation, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, status, intent, playbook, confidence, created_at, updated_at
		 FROM investigations ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query investigations: %w", err)
	}
	defer rows.Close()

	var out []Investigation
	for rows.Next() {
		var inv Investigation
		if err := rows.Scan(&inv.ID, &inv.Status, &inv.Intent, &inv.Playbook, &inv.Confidence, &inv.CreatedAt, &inv.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, inv)
	}
	return out, nil
}

func (m *Manager) Approve(ctx context.Context, id string) error {
	return m.UpdateStatus(ctx, id, "approved")
}

func (m *Manager) Deny(ctx context.Context, id string) error {
	return m.UpdateStatus(ctx, id, "denied")
}

// EnsureApprovalsTable creates the additive approvals table (no alters to
// existing tables). Called lazily by approval methods.
func (m *Manager) EnsureApprovalsTable(ctx context.Context) error {
	_, err := m.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS approvals (
		nonce TEXT PRIMARY KEY,
		investigation_id TEXT NOT NULL,
		step_index INTEGER NOT NULL,
		label TEXT NOT NULL DEFAULT '',
		agent TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		params_hash TEXT NOT NULL,
		approver TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT NOT NULL,
		decided_at TEXT
	)`)
	return err
}

// ApprovalRow is a DB-backed pending-approval row (mirrors playbook schema
// without importing playbook: investigation never imports playbook).
type ApprovalRow struct {
	Nonce           string `json:"nonce"`
	InvestigationID string `json:"investigation_id"`
	StepIndex       int    `json:"step_index"`
	Label           string `json:"label"`
	Agent           string `json:"agent"`
	Action          string `json:"action"`
	ParamsHash      string `json:"params_hash"`
	Approver        string `json:"approver"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
}

// RecordApproval inserts a pending approval row (idempotent on nonce).
func (m *Manager) RecordApproval(ctx context.Context, r ApprovalRow) error {
	if err := m.EnsureApprovalsTable(ctx); err != nil {
		return err
	}
	_, err := m.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO approvals (nonce, investigation_id, step_index, label, agent, action, params_hash, approver, status, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
		r.Nonce, r.InvestigationID, r.StepIndex, r.Label, r.Agent, r.Action, r.ParamsHash, r.Approver, r.ExpiresAt)
	return err
}

// GetApproval fetches one approval row by nonce.
func (m *Manager) GetApproval(ctx context.Context, nonce string) (*ApprovalRow, error) {
	if err := m.EnsureApprovalsTable(ctx); err != nil {
		return nil, err
	}
	var r ApprovalRow
	err := m.db.QueryRowContext(ctx,
		`SELECT nonce, investigation_id, step_index, label, agent, action, params_hash, approver, status, created_at, expires_at
		 FROM approvals WHERE nonce = ?`, nonce).
		Scan(&r.Nonce, &r.InvestigationID, &r.StepIndex, &r.Label, &r.Agent, &r.Action, &r.ParamsHash, &r.Approver, &r.Status, &r.CreatedAt, &r.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("get approval: %w", err)
	}
	return &r, nil
}

// DecideApproval marks a row approved/denied (only from pending; denies
// expired rows closed via ExpireApprovals first by callers).
func (m *Manager) DecideApproval(ctx context.Context, nonce, status string) error {
	if status != "approved" && status != "denied" {
		return fmt.Errorf("invalid approval status %q", status)
	}
	if err := m.EnsureApprovalsTable(ctx); err != nil {
		return err
	}
	res, err := m.db.ExecContext(ctx,
		`UPDATE approvals SET status = ?, decided_at = datetime('now') WHERE nonce = ? AND status = 'pending'`,
		status, nonce)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("approval %s not pending", nonce)
	}
	return nil
}

// ExpireApprovals deny-closes rows past expiry. Returns count expired.
func (m *Manager) ExpireApprovals(ctx context.Context, now string) (int64, error) {
	if err := m.EnsureApprovalsTable(ctx); err != nil {
		return 0, err
	}
	res, err := m.db.ExecContext(ctx,
		`UPDATE approvals SET status = 'denied', decided_at = datetime('now')
		 WHERE status = 'pending' AND expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListApprovals returns pending approval rows (DB-backed listing, no stubs).
func (m *Manager) ListApprovals(ctx context.Context, onlyPending bool) ([]ApprovalRow, error) {
	if err := m.EnsureApprovalsTable(ctx); err != nil {
		return nil, err
	}
	q := `SELECT nonce, investigation_id, step_index, label, agent, action, params_hash, approver, status, created_at, expires_at
		FROM approvals`
	if onlyPending {
		q += ` WHERE status = 'pending'`
	}
	q += ` ORDER BY created_at`
	rows, err := m.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query approvals: %w", err)
	}
	defer rows.Close()
	var out []ApprovalRow
	for rows.Next() {
		var r ApprovalRow
		if err := rows.Scan(&r.Nonce, &r.InvestigationID, &r.StepIndex, &r.Label, &r.Agent, &r.Action, &r.ParamsHash, &r.Approver, &r.Status, &r.CreatedAt, &r.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

type LogEntry struct {
	TS   string         `json:"ts"`
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type LogWriter struct {
	dir string
}

func NewLogWriter(dir string) (*LogWriter, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	return &LogWriter{dir: dir}, nil
}

func ReadInvestigationLog(dir, investigationID string) ([]LogEntry, error) {
	// Traversal-safe: investigation IDs are UUIDs; reject path separators.
	if strings.ContainsAny(investigationID, `/\`) || strings.Contains(investigationID, "..") {
		return nil, fmt.Errorf("invalid investigation id")
	}
	data, err := os.ReadFile(filepath.Join(dir, investigationID+".jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	entries := make([]LogEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (lw *LogWriter) WriteEvent(investigationID string, eventType string, data any) error {
	if strings.ContainsAny(investigationID, `/\`) || strings.Contains(investigationID, "..") {
		return fmt.Errorf("invalid investigation id")
	}
	entry := map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"type": eventType,
		"data": data,
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(
		filepath.Join(lw.dir, investigationID+".jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		return err
	}
	return nil
}
