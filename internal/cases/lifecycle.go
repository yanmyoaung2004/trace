package cases

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Allowed case states and transitions. Terminal states accept reopen.
var allowedTransitions = map[string][]string{
	"open":          {"investigating", "resolved", "closed"},
	"investigating": {"resolved", "closed", "open"},
	"resolved":      {"closed", "open", "investigating"},
	"closed":        {"open", "investigating"},
}

// validTransition reports whether from -> to is legal.
func validTransition(from, to string) bool {
	for _, next := range allowedTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// Transition moves a case through the state machine with org scoping.
// Reopening (resolved/closed -> open/investigating) clears closed_at.
func (m *Manager) Transition(ctx context.Context, orgID, id, to string) error {
	c, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if !validTransition(c.Status, to) {
		return fmt.Errorf("invalid transition %s -> %s", c.Status, to)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if to == "open" || to == "investigating" {
		_, err = m.db.ExecContext(ctx,
			`UPDATE cases SET status = ?, updated_at = ?, closed_at = NULL WHERE id = ? AND org_id = ?`,
			to, now, id, orgID)
		return err
	}
	if to == "closed" || to == "resolved" {
		_, err = m.db.ExecContext(ctx,
			`UPDATE cases SET status = ?, updated_at = ?, closed_at = ? WHERE id = ? AND org_id = ?`,
			to, now, now, id, orgID)
		return err
	}
	_, err = m.db.ExecContext(ctx,
		`UPDATE cases SET status = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
		to, now, id, orgID)
	return err
}

// Ack moves open -> investigating and assigns the owner in one step.
func (m *Manager) Ack(ctx context.Context, orgID, id, owner string) error {
	c, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if c.Status != "open" {
		return fmt.Errorf("ack requires status open, got %s", c.Status)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = m.db.ExecContext(ctx,
		`UPDATE cases SET status = 'investigating', assignee = ?, updated_at = ? WHERE id = ? AND org_id = ? AND status = 'open'`,
		owner, now, id, orgID)
	return err
}

// AssignScoped assigns with org scoping.
func AssignScoped(ctx context.Context, m *Manager, orgID, id, assignee string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := m.db.ExecContext(ctx,
		`UPDATE cases SET assignee = ?, updated_at = ? WHERE id = ? AND org_id = ?`,
		assignee, now, id, orgID)
	return err
}

// ListPage returns a scoped, cursor-paginated case page.
// Cursor is base64(created_at|id); empty cursor starts from the head.
func (m *Manager) ListPage(ctx context.Context, orgID, status, severity string, limit int, cursor string) ([]*Case, string, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	query := `SELECT id, title, description, status, severity, assignee, tags, resolution, created_at, updated_at, closed_at FROM cases WHERE org_id = ?`
	args := []any{orgID}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	if severity != "" {
		query += ` AND severity = ?`
		args = append(args, severity)
	}
	if cursor != "" {
		ts, cid, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", fmt.Errorf("bad cursor: %w", err)
		}
		query += ` AND (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, ts, ts, cid)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []*Case
	for rows.Next() {
		c := &Case{}
		var tagsJSON, closed, assignee, resolution, description sql.NullString
		var id, title, statusV, severityV, created, updated string
		if err := rows.Scan(&id, &title, &description, &statusV, &severityV, &assignee, &tagsJSON, &resolution, &created, &updated, &closed); err != nil {
			return nil, "", err
		}
		c.ID, c.Title, c.Status, c.Severity, c.CreatedAt, c.UpdatedAt = id, title, statusV, severityV, created, updated
		if description.Valid {
			c.Description = description.String
		}
		if assignee.Valid {
			c.Assignee = assignee.String
		}
		if tagsJSON.Valid {
			_ = json.Unmarshal([]byte(tagsJSON.String), &c.Tags)
		}
		if resolution.Valid {
			c.Resolution = resolution.String
		}
		if closed.Valid {
			v := closed.String
			c.ClosedAt = &v
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

func encodeCursor(ts, id string) string {
	return base64.URLEncoding.EncodeToString([]byte(ts + "|" + id))
}

func decodeCursor(cursor string) (string, string, error) {
	raw, err := base64.URLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("malformed cursor")
	}
	return parts[0], parts[1], nil
}

// RateLimiter bounds auto-case explosions per (rule, entity).
type RateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewRateLimiter allows max events per window per (rule, entity).
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	if max <= 0 {
		max = 5
	}
	if window <= 0 {
		window = time.Hour
	}
	return &RateLimiter{hits: map[string][]time.Time{}, max: max, window: window}
}

// Allow reports whether an auto-case may be created for (rule, entity).
func (r *RateLimiter) Allow(rule, entity string) bool {
	if entity == "" {
		entity = "global"
	}
	key := rule + "|" + entity
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-r.window)
	kept := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.max {
		r.hits[key] = kept
		return false
	}
	r.hits[key] = append(kept, now)
	return true
}
