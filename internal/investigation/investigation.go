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

func (m *Manager) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE investigations SET status = ?, updated_at = datetime('now') WHERE id = ?`, status, id)
	return err
}

func (m *Manager) ListPendingApprovals(ctx context.Context) ([]Investigation, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, status, intent, playbook, created_at, updated_at
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

type LogEntry struct {
	TS   string         `json:"ts"`
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type LogWriter struct {
	dir string
}

func NewLogWriter(dir string) (*LogWriter, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	return &LogWriter{dir: dir}, nil
}

func ReadInvestigationLog(dir, investigationID string) ([]LogEntry, error) {
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
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"type":  eventType,
		"data":  data,
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(
		filepath.Join(lw.dir, investigationID+".jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
