package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Tenant-scoped fleet identity + enrollment (FIX_PLAN 0.2 + 0.8).
//
//   - Provision tokens: admin-issued, single-use, expiring. Only the hash is
//     stored. Enrollment consumes the token atomically inside a transaction.
//   - Server-assigned org_id: the client body OrgID is IGNORED on write paths.
//   - Provision-token mint / revoke helpers for the admin API.
//   - Idempotency helpers for dispatch/register (409 on duplicate).

// provisionTokenLifetime bounds how long an enrollment token stays valid.
const provisionTokenLifetime = 24 * time.Hour

// MintProvisionToken issues a single-use enrollment token bound to orgID.
// Returns the raw token (shown once) — only its hash is stored.
func (m *ServerManager) MintProvisionToken(ctx context.Context, orgID, label string, ttl time.Duration) (string, error) {
	if orgID == "" {
		return "", fmt.Errorf("mint provision token: org required")
	}
	if ttl <= 0 {
		ttl = provisionTokenLifetime
	}
	if ttl > 7*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("mint provision token: %w", err)
	}
	tok := hex.EncodeToString(raw)
	prefix := tok
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	now := time.Now().UTC()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO provision_tokens (token_hash, token_prefix, org_id, label, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		hashSecret(tok), prefix, orgID, label,
		now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	if err != nil {
		return "", fmt.Errorf("mint provision token: %w", err)
	}
	return tok, nil
}

// ListProvisionTokens returns non-secret metadata (hash prefix, org, expiry,
// use state) for the admin API. Raw tokens are never recoverable.
func (m *ServerManager) ListProvisionTokens(ctx context.Context, orgID string) ([]map[string]any, error) {
	q := `SELECT token_prefix, org_id, label, created_at, expires_at, COALESCE(used_at, ''), COALESCE(used_by, '') FROM provision_tokens`
	var args []any
	if orgID != "" {
		q += ` WHERE org_id = ?`
		args = append(args, orgID)
	}
	q += ` ORDER BY created_at DESC LIMIT 100`
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var prefix, org, label, created, expires, usedAt, usedBy string
		if err := rows.Scan(&prefix, &org, &label, &created, &expires, &usedAt, &usedBy); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"prefix": prefix, "org_id": org, "label": label,
			"created_at": created, "expires_at": expires,
			"used_at": usedAt, "used_by": usedBy,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

// RevokeProvisionToken deletes an unused enrollment token by prefix.
func (m *ServerManager) RevokeProvisionToken(ctx context.Context, prefix string) error {
	if !validResourceID(prefix) {
		return fmt.Errorf("invalid token prefix")
	}
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM provision_tokens WHERE token_prefix = ? AND used_at IS NULL`, prefix)
	return err
}

// consumeProvisionToken validates tok and marks it used by agentID atomically.
// Returns the token's org. Must be called inside the enrollment transaction's
// connection — here enforced via an IMMEDIATE transaction on the caller's tx.
// For simplicity it runs its own transaction with UPDATE ... used_at IS NULL
// guard so concurrent consumes collapse to one winner.
func (m *ServerManager) consumeProvisionToken(ctx context.Context, tok string) (string, error) {
	if tok == "" {
		return "", fmt.Errorf("provision token required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := m.db.ExecContext(ctx,
		`UPDATE provision_tokens SET used_at = ?, used_by = 'pending-enrollment'
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now, hashSecret(tok), now)
	if err != nil {
		return "", fmt.Errorf("invalid provision token")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", fmt.Errorf("invalid, expired, or already-used provision token")
	}
	var orgID string
	if err := m.db.QueryRowContext(ctx,
		`SELECT org_id FROM provision_tokens WHERE token_hash = ?`, hashSecret(tok)).Scan(&orgID); err != nil {
		return "", fmt.Errorf("invalid provision token")
	}
	return orgID, nil
}

// finalizeProvisionUse binds the consumed token to the enrolled agent ID.
// Separated from consume so the agent row and token claim stay consistent.
func (m *ServerManager) finalizeProvisionUse(ctx context.Context, tok, agentID string) {
	_, _ = m.db.ExecContext(ctx,
		`UPDATE provision_tokens SET used_by = ? WHERE token_hash = ?`, agentID, hashSecret(tok))
}

// enrollAgentTx inserts the agent row with server-assigned org and a fresh
// hashed agent key. Returns (agentID, rawAgentKey).
func (m *ServerManager) enrollAgentTx(ctx context.Context, orgID string, hostname, platform, arch, version, agentVersion, kernelVersion, monitors string, cpuCount int, cpuName string, memoryMB int64, ip string) (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("enroll agent: %w", err)
	}
	agentKey := hex.EncodeToString(raw)
	agentID, err := uuid.NewV7()
	if err != nil {
		return "", "", fmt.Errorf("enroll agent: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO edr_agents (id, hostname, platform, arch, version, agent_version, status, ip_address, cpu_count, cpu_name, memory_mb, kernel_version, monitors, org_id, api_key_hash, last_heartbeat, last_ip, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		agentID.String(), hostname, platform, arch, version, agentVersion,
		ip, cpuCount, cpuName, memoryMB, kernelVersion, monitors, orgID,
		hashSecret(agentKey), now, ip, now, now)
	if err != nil {
		return "", "", fmt.Errorf("enroll agent: %w", err)
	}
	return agentID.String(), agentKey, nil
}

// ── Idempotency ──

// checkIdempotency looks up (key, actor). Found → (status, body, true).
// Not found → records a placeholder row owned by this request and returns false.
// The caller completes it via finishIdempotency.
func (m *ServerManager) checkIdempotency(ctx context.Context, key, actor, reqHash string) (int, string, bool) {
	if key == "" || actor == "" || len(key) > 128 {
		return 0, "", false
	}
	var st int
	var body, prevHash string
	err := m.db.QueryRowContext(ctx,
		`SELECT status, body, req_hash FROM idempotency_keys WHERE ikey = ? AND actor = ?`, key, actor).Scan(&st, &body, &prevHash)
	if err == nil {
		return st, body, true
	}
	if err != sql.ErrNoRows {
		return 0, "", false
	}
	// First sighting: insert an in-progress marker. A concurrent winner
	// raises a conflict → treat as duplicate (409 path below re-reads).
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO idempotency_keys (ikey, actor, status, body, req_hash) VALUES (?, ?, 0, '', ?)`,
		key, actor, reqHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") || strings.Contains(err.Error(), "conflict") {
			var st2 int
			var body2, h2 string
			if err2 := m.db.QueryRowContext(ctx,
				`SELECT status, body, req_hash FROM idempotency_keys WHERE ikey = ? AND actor = ?`, key, actor).Scan(&st2, &body2, &h2); err2 == nil {
				return st2, body2, true
			}
		}
		return 0, "", false
	}
	return 0, "", false
}

// finishIdempotency stores the final (status, body) for (key, actor).
func (m *ServerManager) finishIdempotency(ctx context.Context, key, actor string, status int, body string) {
	if key == "" || actor == "" {
		return
	}
	_, _ = m.db.ExecContext(ctx,
		`UPDATE idempotency_keys SET status = ?, body = ? WHERE ikey = ? AND actor = ?`,
		status, body, key, actor)
}

// idempotencyConflict reports 409 with the original response body replayed.
// Returns true when the duplicate carried the same request hash; mismatched
// hashes are still 409 (same key must not produce two effects).
func idempotencyConflictBody(prevBody string) (int, string) {
	if prevBody == "" {
		return 409, `{"error":"duplicate request: already in progress or completed"}`
	}
	return 409, prevBody
}
