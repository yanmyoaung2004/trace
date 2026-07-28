package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const signingKeySize = 32

// Entry is a single audit log entry with HMAC chain.
type Entry struct {
	ID           int64  `json:"id"`
	Timestamp    string `json:"timestamp"`
	ActorID      string `json:"actor_id"`
	ActorEmail   string `json:"actor_email"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Details      string `json:"details"`
	PreviousHash string `json:"previous_hash"`
	Signature    string `json:"signature"`
}

// Logger writes append-only audit entries with HMAC chaining.
type Logger struct {
	db        *sql.DB
	signingKey []byte
}

// New creates an audit logger. If signingKey is nil, a random key is generated.
func New(db *sql.DB, signingKey []byte) (*Logger, error) {
	if signingKey == nil {
		signingKey = make([]byte, signingKeySize)
		if _, err := rand.Read(signingKey); err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
	}

	l := &Logger{db: db, signingKey: signingKey}

	// Create table if not exists
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			actor_email TEXT NOT NULL,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			details TEXT NOT NULL DEFAULT '{}',
			previous_hash TEXT NOT NULL DEFAULT '',
			signature TEXT NOT NULL
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("create audit_log table: %w", err)
	}

	return l, nil
}

// Write records an audit entry with HMAC-SHA256 over (previous_hash + timestamp + actor + action + resource + details).
func (l *Logger) Write(ctx context.Context, entry Entry) error {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Get previous entry's hash for chaining
	prevHash, err := l.getLatestHash(ctx)
	if err != nil {
		return fmt.Errorf("get prev hash: %w", err)
	}
	entry.PreviousHash = prevHash

	// Compute signature
	sigInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		prevHash, entry.Timestamp, entry.ActorID, entry.ActorEmail,
		entry.Action, entry.ResourceType, entry.ResourceID)
	mac := hmac.New(sha256.New, l.signingKey)
	mac.Write([]byte(sigInput))
	entry.Signature = hex.EncodeToString(mac.Sum(nil))

	_, err = l.db.ExecContext(ctx,
		`INSERT INTO audit_log (timestamp, actor_id, actor_email, action, resource_type, resource_id, details, previous_hash, signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.ActorID, entry.ActorEmail, entry.Action,
		entry.ResourceType, entry.ResourceID, entry.Details,
		entry.PreviousHash, entry.Signature)
	return err
}

// Query retrieves audit entries with optional filters.
func (l *Logger) Query(ctx context.Context, filter QueryFilter) ([]Entry, error) {
	where := []string{"1=1"}
	args := []any{}

	if filter.ResourceType != "" {
		where = append(where, "resource_type = ?")
		args = append(args, filter.ResourceType)
	}
	if filter.ResourceID != "" {
		where = append(where, "resource_id = ?")
		args = append(args, filter.ResourceID)
	}
	if filter.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, filter.ActorID)
	}
	if filter.Action != "" {
		where = append(where, "action = ?")
		args = append(args, filter.Action)
	}
	if filter.Since != "" {
		where = append(where, "timestamp >= ?")
		args = append(args, filter.Since)
	}
	if filter.Until != "" {
		where = append(where, "timestamp <= ?")
		args = append(args, filter.Until)
	}

	limit := 100
	if filter.Limit > 0 && filter.Limit <= 1000 {
		limit = filter.Limit
	}

	query := fmt.Sprintf(
		`SELECT id, timestamp, actor_id, actor_email, action, resource_type, resource_id, details, previous_hash, signature
		 FROM audit_log WHERE %s ORDER BY id DESC LIMIT ?`, strings.Join(where, " AND "))
	args = append(args, limit)

	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ActorID, &e.ActorEmail,
			&e.Action, &e.ResourceType, &e.ResourceID, &e.Details, &e.PreviousHash, &e.Signature); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Verify checks the integrity of the entire audit log.
// Returns (valid bool, errors []string).
func (l *Logger) Verify(ctx context.Context) (bool, []string) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT id, timestamp, actor_id, actor_email, action, resource_type, resource_id, details, previous_hash, signature
		 FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return false, []string{fmt.Sprintf("query: %v", err)}
	}
	defer rows.Close()

	var errors []string
	var prevHash string

	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ActorID, &e.ActorEmail,
			&e.Action, &e.ResourceType, &e.ResourceID, &e.Details, &e.PreviousHash, &e.Signature); err != nil {
			errors = append(errors, fmt.Sprintf("scan row: %v", err))
			continue
		}

		// Check chain
		if e.PreviousHash != prevHash {
			errors = append(errors, fmt.Sprintf("chain broken at entry %d: expected prev_hash=%s, got %s",
				e.ID, prevHash, e.PreviousHash))
		}

		// Verify signature
		sigInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			e.PreviousHash, e.Timestamp, e.ActorID, e.ActorEmail,
			e.Action, e.ResourceType, e.ResourceID)
		mac := hmac.New(sha256.New, l.signingKey)
		mac.Write([]byte(sigInput))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		if e.Signature != expectedSig {
			errors = append(errors, fmt.Sprintf("signature mismatch at entry %d: expected %s, got %s",
				e.ID, expectedSig, e.Signature))
		}

		prevHash = e.Signature
	}

	return len(errors) == 0, errors
}

func (l *Logger) getLatestHash(ctx context.Context) (string, error) {
	var hash string
	err := l.db.QueryRowContext(ctx,
		`SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hash, nil
}

// QueryFilter for filtering audit entries.
type QueryFilter struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	Since        string `json:"since"` // RFC3339
	Until        string `json:"until"` // RFC3339
	Limit        int    `json:"limit"`
}

// MarshalJSON serializes details as JSON.
func MarshalDetails(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}
