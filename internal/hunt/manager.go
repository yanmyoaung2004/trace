package hunt

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/db"
)

type Hunt struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Schedule       string         `json:"schedule"`
	Playbook       string         `json:"playbook"`
	Params         map[string]any `json:"params"`
	Scope          string         `json:"scope"`
	NotifySeverity int            `json:"notify_severity"`
	Status         string         `json:"status"`
	LastRun        *string        `json:"last_run,omitempty"`
	NextRun        *string        `json:"next_run,omitempty"`
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
}

type Manager struct {
	db *db.DB
}

func NewManager(database *db.DB) *Manager {
	return &Manager{db: database}
}

func (m *Manager) Create(ctx context.Context, name, description, schedule, playbook string, params map[string]any, scope string, notifySeverity int) (*Hunt, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	nextRun := computeNextRun(schedule)

	paramsJSON, _ := json.Marshal(params)

	id := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO hunts (id, name, description, schedule, playbook, params, scope, notify_severity, status, next_run, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		id, name, description, schedule, playbook, string(paramsJSON), scope, notifySeverity, nextRun, now, now)
	if err != nil {
		return nil, fmt.Errorf("create hunt: %w", err)
	}

	return m.Get(ctx, id)
}

func (m *Manager) Get(ctx context.Context, id string) (*Hunt, error) {
	var h Hunt
	var paramsStr, nextRun, lastRun sql.NullString
	err := m.db.QueryRowContext(ctx,
		`SELECT id, name, description, schedule, playbook, params, scope, notify_severity, status, last_run, next_run, created_at, updated_at FROM hunts WHERE id = ?`, id).
		Scan(&h.ID, &h.Name, &h.Description, &h.Schedule, &h.Playbook, &paramsStr, &h.Scope, &h.NotifySeverity, &h.Status, &lastRun, &nextRun, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get hunt: %w", err)
	}

	if paramsStr.Valid {
		json.Unmarshal([]byte(paramsStr.String), &h.Params)
	}
	if h.Params == nil {
		h.Params = make(map[string]any)
	}
	if nextRun.Valid {
		h.NextRun = &nextRun.String
	}
	if lastRun.Valid {
		h.LastRun = &lastRun.String
	}

	return &h, nil
}

func (m *Manager) GetByName(ctx context.Context, name string) (*Hunt, error) {
	var id string
	err := m.db.QueryRowContext(ctx, `SELECT id FROM hunts WHERE name = ?`, name).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("hunt %q not found", name)
	}
	return m.Get(ctx, id)
}

func (m *Manager) List(ctx context.Context, status string) ([]*Hunt, error) {
	query := `SELECT id FROM hunts`
	var args []any
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hunts []*Hunt
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		h, err := m.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		hunts = append(hunts, h)
	}
	return hunts, nil
}

func (m *Manager) Update(ctx context.Context, id string, updates map[string]any) error {
	now := time.Now().UTC().Format(time.RFC3339)
	updates["updated_at"] = now

	if s, ok := updates["schedule"]; ok {
		updates["next_run"] = computeNextRun(s.(string))
	}

	for k, v := range updates {
		if _, err := m.db.ExecContext(ctx,
			fmt.Sprintf(`UPDATE hunts SET %s = ? WHERE id = ?`, k), v, id); err != nil {
			return fmt.Errorf("update hunt %s: %w", k, err)
		}
	}
	return nil
}

func (m *Manager) Pause(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE hunts SET status = 'paused', updated_at = datetime('now') WHERE id = ?`, id)
	return err
}

func (m *Manager) Resume(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	nextRun := computeNextRunFromDB(ctx, m.db, id)
	if nextRun == "" {
		nextRun = time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	}
	_, err := m.db.ExecContext(ctx,
		`UPDATE hunts SET status = 'active', next_run = ?, updated_at = ? WHERE id = ?`, nextRun, now, id)
	return err
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	_, err := m.db.ExecContext(ctx, `DELETE FROM hunts WHERE id = ?`, id)
	return err
}

func (m *Manager) DueHunts(ctx context.Context) ([]*Hunt, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := m.db.QueryContext(ctx,
		`SELECT id FROM hunts WHERE status = 'active' AND (next_run IS NULL OR next_run <= ?) ORDER BY next_run ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hunts []*Hunt
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		h, err := m.Get(ctx, id)
		if err != nil {
			continue
		}
		hunts = append(hunts, h)
	}
	return hunts, nil
}

func (m *Manager) MarkRun(ctx context.Context, id string) {
	now := time.Now().UTC().Format(time.RFC3339)

	h, err := m.Get(ctx, id)
	if err != nil {
		return
	}

	nextRun := computeNextRun(h.Schedule)
	if nextRun == "" {
		nextRun = time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	}

	m.db.ExecContext(ctx,
		`UPDATE hunts SET last_run = ?, next_run = ?, updated_at = ? WHERE id = ?`,
		now, nextRun, now, id)
}

func computeNextRun(schedule string) string {
	dur, err := parseSchedule(schedule)
	if err != nil {
		return ""
	}
	return time.Now().UTC().Add(dur).Format(time.RFC3339)
}

func computeNextRunFromDB(ctx context.Context, db *db.DB, id string) string {
	var schedule string
	err := db.QueryRowContext(ctx, `SELECT schedule FROM hunts WHERE id = ?`, id).Scan(&schedule)
	if err != nil {
		return ""
	}
	return computeNextRun(schedule)
}

func parseSchedule(schedule string) (time.Duration, error) {
	if schedule == "" {
		return 0, fmt.Errorf("empty schedule")
	}
	return time.ParseDuration(schedule)
}

func BuildDefaultHunts() []struct {
	Name           string
	Description    string
	Schedule       string
	Playbook       string
	Params         map[string]any
	Scope          string
	NotifySeverity int
} {
	return []struct {
		Name           string
		Description    string
		Schedule       string
		Playbook       string
		Params         map[string]any
		Scope          string
		NotifySeverity int
	}{
		{
			Name:           "known-malware-scan",
			Description:    "Scan for known malware hashes on the local system every 6 hours",
			Schedule:       "6h",
			Playbook:       "hash-lookup",
			Params:         nil,
			Scope:          "self",
			NotifySeverity: 5,
		},
		{
			Name:           "compliance-audit",
			Description:    "Run daily CIS benchmark compliance scan",
			Schedule:       "24h",
			Playbook:       "compliance-scan",
			Params:         nil,
			Scope:          "self",
			NotifySeverity: 3,
		},
		{
			Name:           "rootkit-sweep",
			Description:    "Daily global filesystem scan for rootkit signatures",
			Schedule:       "24h",
			Playbook:       "rootkit-scan",
			Params:         nil,
			Scope:          "self",
			NotifySeverity: 5,
		},
		{
			Name:           "k8s-audit",
			Description:    "Hourly K8s RBAC audit — detect privileged pods, secret access, clusterrole changes",
			Schedule:       "1h",
			Playbook:       "log-analysis",
			Params:         nil,
			Scope:          "self",
			NotifySeverity: 4,
		},
	}
}

func init() {
	_ = uuid.New
	_ = json.Marshal
}
