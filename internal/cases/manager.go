package cases

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/db"
)

type Case struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Severity    string   `json:"severity"`
	Assignee    string   `json:"assignee,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Resolution  string   `json:"resolution,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	ClosedAt    *string  `json:"closed_at,omitempty"`
}

type Event struct {
	ID        string `json:"id"`
	CaseID    string `json:"case_id"`
	EventType string `json:"event_type"`
	Content   string `json:"content"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

type IOC struct {
	ID          string `json:"id"`
	CaseID      string `json:"case_id"`
	IOCType     string `json:"ioc_type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	CreatedAt   string `json:"created_at"`
}

type Manager struct {
	db *db.DB
}

func NewManager(database *db.DB) *Manager {
	return &Manager{db: database}
}

func (m *Manager) Create(ctx context.Context, title, description, severity string) (*Case, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id := uuid.New().String()

	if severity == "" {
		severity = "medium"
	}
	status := "open"

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO cases (id, title, description, status, severity, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, title, description, status, severity, now, now)
	if err != nil {
		return nil, fmt.Errorf("create case: %w", err)
	}

	c, _ := m.Get(ctx, id)
	return c, nil
}

func (m *Manager) Get(ctx context.Context, id string) (*Case, error) {
	c := &Case{}
	var tagsJSON, closed sql.NullString
	err := m.db.QueryRowContext(ctx,
		`SELECT id, title, description, status, severity, assignee, tags, resolution, created_at, updated_at, closed_at FROM cases WHERE id = ?`, id).
		Scan(&c.ID, &c.Title, &c.Description, &c.Status, &c.Severity, &c.Assignee, &tagsJSON, &c.Resolution, &c.CreatedAt, &c.UpdatedAt, &closed)
	if err != nil {
		return nil, fmt.Errorf("get case: %w", err)
	}
	if tagsJSON.Valid {
		json.Unmarshal([]byte(tagsJSON.String), &c.Tags)
	}
	if closed.Valid {
		c.ClosedAt = &closed.String
	}
	return c, nil
}

func (m *Manager) List(ctx context.Context, status, severity string) ([]*Case, error) {
	query := `SELECT id FROM cases WHERE 1=1`
	var args []any
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	if severity != "" {
		query += ` AND severity = ?`
		args = append(args, severity)
	}
	query += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cases []*Case
	for rows.Next() {
		var id string
		rows.Scan(&id)
		c, err := m.Get(ctx, id)
		if err != nil {
			continue
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func (m *Manager) UpdateStatus(ctx context.Context, id, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	q := `UPDATE cases SET status = ?, updated_at = ?`
	if status == "closed" || status == "resolved" {
		q += `, closed_at = ?`
	}
	q += ` WHERE id = ?`

	var err error
	if status == "closed" || status == "resolved" {
		_, err = m.db.ExecContext(ctx, q, status, now, now, id)
	} else {
		_, err = m.db.ExecContext(ctx, q, status, now, id)
	}
	return err
}

func (m *Manager) Assign(ctx context.Context, id, assignee string) error {
	_, err := m.db.ExecContext(ctx,
		`UPDATE cases SET assignee = ?, updated_at = datetime('now') WHERE id = ?`, assignee, id)
	return err
}

func (m *Manager) Resolve(ctx context.Context, id, resolution string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := m.db.ExecContext(ctx,
		`UPDATE cases SET status = 'resolved', resolution = ?, closed_at = ?, updated_at = ? WHERE id = ?`,
		resolution, now, now, id)
	return err
}

func (m *Manager) AddEvent(ctx context.Context, caseID, eventType, content, source string) (*Event, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	id := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO case_events (id, case_id, event_type, content, source, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, caseID, eventType, content, source, now)
	if err != nil {
		return nil, err
	}
	return &Event{ID: id, CaseID: caseID, EventType: eventType, Content: content, Source: source, CreatedAt: now}, nil
}

func (m *Manager) GetEvents(ctx context.Context, caseID string) ([]*Event, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, case_id, event_type, content, source, created_at FROM case_events WHERE case_id = ? ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e := &Event{}
		if err := rows.Scan(&e.ID, &e.CaseID, &e.EventType, &e.Content, &e.Source, &e.CreatedAt); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events, nil
}

func (m *Manager) AddIOC(ctx context.Context, caseID, iocType, value, description string) (*IOC, error) {
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	iocType = strings.ToLower(iocType)
	switch iocType {
	case "ip", "ipv4", "ipv6":
		iocType = "ip"
	case "domain":
	case "url":
	case "hash", "md5", "sha1", "sha256":
		iocType = "hash"
	case "email":
	case "file", "path":
		iocType = "filepath"
	default:
		iocType = "unknown"
	}

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO case_iocs (id, case_id, ioc_type, value, description, source, created_at) VALUES (?, ?, ?, ?, ?, 'manual', ?)`,
		id, caseID, iocType, value, description, now)
	if err != nil {
		return nil, err
	}
	return &IOC{ID: id, CaseID: caseID, IOCType: iocType, Value: value, Description: description, CreatedAt: now}, nil
}

func (m *Manager) GetIOCs(ctx context.Context, caseID string) ([]*IOC, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, case_id, ioc_type, value, description, source, created_at FROM case_iocs WHERE case_id = ? ORDER BY created_at ASC`, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var iocs []*IOC
	for rows.Next() {
		i := &IOC{}
		if err := rows.Scan(&i.ID, &i.CaseID, &i.IOCType, &i.Value, &i.Description, &i.Source, &i.CreatedAt); err != nil {
			continue
		}
		iocs = append(iocs, i)
	}
	return iocs, nil
}

func init() {
	_ = uuid.New
	_ = json.Marshal
}
