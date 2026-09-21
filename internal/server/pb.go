package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/db"
	"github.com/yanmyoaung2004/trace/internal/investigation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type NodeInfo struct {
	ID        string `json:"id"`
	Hostname  string `json:"hostname"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	LastSeen  string `json:"last_seen"`
	CreatedAt string `json:"created_at"`
}

type ServerInvestigation struct {
	ID         string   `json:"id"`
	NodeID     string   `json:"node_id"`
	Status     string   `json:"status"`
	Intent     string   `json:"intent"`
	Playbook   string   `json:"playbook,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
	Report     string   `json:"report,omitempty"`
	SourceEdge string   `json:"source_edge,omitempty"`
	CreatedAt  string   `json:"created_at"`
	UpdatedAt  string   `json:"updated_at"`
}

type ServerManager struct {
	db *db.DB
}

func NewServerManager(database *db.DB) *ServerManager {
	return &ServerManager{db: database}
}

func (m *ServerManager) Migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS server_nodes (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			version TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			org_id TEXT NOT NULL DEFAULT '',
			last_heartbeat TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_server_nodes_org ON server_nodes(org_id)`,
		`CREATE TABLE IF NOT EXISTS server_investigations (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL REFERENCES server_nodes(id),
			status TEXT NOT NULL,
			intent TEXT NOT NULL,
			playbook TEXT,
			confidence REAL,
			summary TEXT,
			indicators TEXT,
			report TEXT,
			source_edge TEXT,
			org_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_node ON server_investigations(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_status ON server_investigations(status)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_created ON server_investigations(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_org ON server_investigations(org_id)`,
		// User keys are stored as SHA-256 hashes only (api_key_hash); the
		// legacy plaintext api_key column is kept for upgrade backfill and
		// cleared once hashed. api_key_prefix (first 8 hex chars) is for
		// operator identification in logs — never enough to authenticate.
		`CREATE TABLE IF NOT EXISTS server_users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'analyst',
			api_key TEXT,
			api_key_hash TEXT NOT NULL DEFAULT '',
			api_key_prefix TEXT NOT NULL DEFAULT '',
			api_key_expires_at TEXT,
			org_id TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT 'full',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_server_users_keyhash ON server_users(api_key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_server_users_org ON server_users(org_id)`,
		`CREATE TABLE IF NOT EXISTS server_correlations (
			id TEXT PRIMARY KEY,
			ioc TEXT NOT NULL,
			node_ids TEXT NOT NULL,
			count INTEGER NOT NULL DEFAULT 1,
			confidence REAL DEFAULT 0.5,
			org_id TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_corr_ioc ON server_correlations(ioc)`,
		`CREATE INDEX IF NOT EXISTS idx_corr_org ON server_correlations(org_id)`,
		// edr_agents.org_id is server-assigned at enrollment (provision token
		// or admin), never taken from the client body.
		`CREATE TABLE IF NOT EXISTS edr_agents (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			platform TEXT NOT NULL,
			arch TEXT NOT NULL,
			version TEXT NOT NULL,
			agent_version TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			ip_address TEXT,
			cpu_count INTEGER DEFAULT 0,
			memory_mb INTEGER DEFAULT 0,
			kernel_version TEXT,
			cpu_name TEXT DEFAULT '',
			monitors TEXT,
			org_id TEXT NOT NULL DEFAULT '',
			api_key_hash TEXT,
			last_heartbeat TEXT,
			last_ip TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_agents_org ON edr_agents(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_agents_status ON edr_agents(status)`,
		`CREATE TABLE IF NOT EXISTS edr_events (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES edr_agents(id),
			event_type TEXT NOT NULL,
			severity INTEGER NOT NULL DEFAULT 1,
			data TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT '',
			timestamp TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_agent ON edr_events(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_type ON edr_events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_severity ON edr_events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_time ON edr_events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_org ON edr_events(org_id)`,
		`CREATE TABLE IF NOT EXISTS edr_actions (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES edr_agents(id),
			action_type TEXT NOT NULL,
			target TEXT,
			params TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'pending',
			result TEXT,
			error TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			completed_at TEXT,
			timeout_seconds INTEGER NOT NULL DEFAULT 30,
			org_id TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_actions_agent ON edr_actions(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_actions_status ON edr_actions(status)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_actions_org ON edr_actions(org_id)`,
		`CREATE TABLE IF NOT EXISTS edr_fp_counters (
			rule_name TEXT NOT NULL,
			process_name TEXT NOT NULL,
			dismissals INTEGER NOT NULL DEFAULT 1,
			throttled INTEGER NOT NULL DEFAULT 0,
			org_id TEXT NOT NULL DEFAULT '',
			last_seen TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (rule_name, process_name)
		)`,
		`CREATE TABLE IF NOT EXISTS compliance_snapshots (
			id TEXT PRIMARY KEY,
			hostname TEXT NOT NULL,
			framework TEXT NOT NULL,
			score REAL NOT NULL,
			total INTEGER NOT NULL,
			passed INTEGER NOT NULL,
			failed INTEGER NOT NULL,
			not_covered INTEGER NOT NULL,
			org_id TEXT NOT NULL DEFAULT '',
			snapshot TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cs_host ON compliance_snapshots(hostname)`,
		`CREATE INDEX IF NOT EXISTS idx_cs_framework ON compliance_snapshots(framework)`,
		`CREATE INDEX IF NOT EXISTS idx_cs_org ON compliance_snapshots(org_id)`,
		`CREATE TABLE IF NOT EXISTS server_orgs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		// Provision tokens: admin-issued, single-use, expiring enrollment
		// credentials. Only the hash is stored.
		`CREATE TABLE IF NOT EXISTS provision_tokens (
			token_hash TEXT PRIMARY KEY,
			token_prefix TEXT NOT NULL DEFAULT '',
			org_id TEXT NOT NULL,
			label TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT NOT NULL,
			used_at TEXT,
			used_by TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_provision_org ON provision_tokens(org_id)`,
		// Idempotency keys: (key, actor) dedupes retried mutations.
		`CREATE TABLE IF NOT EXISTS idempotency_keys (
			ikey TEXT NOT NULL,
			actor TEXT NOT NULL,
			status INTEGER NOT NULL,
			body TEXT NOT NULL,
			req_hash TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (ikey, actor)
		)`,
	}

	for _, q := range queries {
		if _, err := m.db.Exec(q); err != nil {
			return fmt.Errorf("server migrate: %w", err)
		}
	}

	// Upgrade path for pre-tenancy databases: additive columns only, never
	// destructive. Legacy rows keep org_id='' and are invisible to tenants
	// (tenant queries match strict equality; see orgPredicate). Errors are
	// ignored: the column/index may already exist.
	for _, stmt := range []string{
		`ALTER TABLE edr_agents ADD COLUMN cpu_name TEXT DEFAULT ''`,
		`ALTER TABLE server_users ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_users ADD COLUMN api_key_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_users ADD COLUMN api_key_prefix TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_users ADD COLUMN api_key_expires_at TEXT`,
		`ALTER TABLE server_users ADD COLUMN scope TEXT NOT NULL DEFAULT 'full'`,
		`ALTER TABLE edr_agents ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE edr_events ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_nodes ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_investigations ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE server_correlations ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE edr_actions ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE edr_fp_counters ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE compliance_snapshots ADD COLUMN org_id TEXT NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS idx_server_nodes_org ON server_nodes(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_org ON server_investigations(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_server_users_keyhash ON server_users(api_key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_server_users_org ON server_users(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_corr_org ON server_correlations(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_agents_org ON edr_agents(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_org ON edr_events(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_actions_org ON edr_actions(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cs_org ON compliance_snapshots(org_id)`,
	} {
		_, _ = m.db.Exec(stmt)
	}

	// Backfill: hash legacy plaintext user keys, then clear the plaintext
	// column. Runs on every start; rows already hashed are skipped.
	if err := m.backfillUserKeyHashes(context.Background()); err != nil {
		return fmt.Errorf("server migrate key backfill: %w", err)
	}

	return nil
}

// backfillUserKeyHashes moves any remaining plaintext api_key values to
// api_key_hash/api_key_prefix and clears the plaintext column.
func (m *ServerManager) backfillUserKeyHashes(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, api_key FROM server_users WHERE api_key IS NOT NULL AND api_key <> ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type pending struct{ id, key string }
	var work []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.key); err != nil {
			return err
		}
		work = append(work, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range work {
		h := hashSecret(p.key)
		prefix := p.key
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		if _, err := m.db.ExecContext(ctx,
			`UPDATE server_users SET api_key_hash = ?, api_key_prefix = ?, api_key = '' WHERE id = ?`,
			h, prefix, p.id); err != nil {
			return err
		}
	}
	return nil
}

func (m *ServerManager) RegisterNode(ctx context.Context, hostname, version string) (*NodeInfo, error) {
	if strings.TrimSpace(hostname) == "" || len(hostname) > 256 {
		return nil, fmt.Errorf("register node: hostname required")
	}
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)
	orgID, _ := ctx.Value(ctxKeyOrg).(string)

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO server_nodes (id, hostname, version, status, org_id, last_heartbeat, created_at) VALUES (?, ?, ?, 'active', ?, ?, ?)`,
		id, hostname, version, orgID, now, now)
	if err != nil {
		return nil, fmt.Errorf("register node: %w", err)
	}

	return &NodeInfo{
		ID:        id,
		Hostname:  hostname,
		Version:   version,
		Status:    "active",
		LastSeen:  now,
		CreatedAt: now,
	}, nil
}

func (m *ServerManager) Heartbeat(ctx context.Context, nodeID string) error {
	if !validResourceID(nodeID) {
		return status.Error(codes.InvalidArgument, "invalid node id")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	q := `UPDATE server_nodes SET last_heartbeat = ?, status = 'active' WHERE id = ?`
	var args []any
	args = append(args, now, nodeID)
	q += orgPredicate(ctx, &args)
	result, err := m.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return status.Error(codes.NotFound, "node not found")
	}
	return nil
}
func (m *ServerManager) PushInvestigation(ctx context.Context, nodeID, invID, statusStr, intent, playbook, summary string, confidence *float64, indicators []string, report string) error {
	if !validResourceID(nodeID) || !validResourceID(invID) {
		return fmt.Errorf("push investigation: invalid id")
	}
	if len(intent) > 4096 || len(summary) > 8192 || len(report) > 65536 {
		return fmt.Errorf("push investigation: payload too large")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	indJSON, _ := json.Marshal(indicators)
	orgID, _ := ctx.Value(ctxKeyOrg).(string)

	_, err := m.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO server_investigations
		 (id, node_id, status, intent, playbook, confidence, summary, indicators, report, source_edge, org_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM server_investigations WHERE id = ?), ?), ?)`,
		invID, nodeID, statusStr, intent, playbook, confidence, summary, string(indJSON), report, nodeID, orgID, invID, now, now)
	if err != nil {
		return fmt.Errorf("push investigation: %w", err)
	}

	for _, ioc := range indicators {
		if ioc == "" || len(ioc) > 256 {
			continue
		}
		m.updateCorrelation(ctx, ioc, nodeID)
	}

	return nil
}

func (m *ServerManager) SyncLocalInvestigations(ctx context.Context, invMgr *investigation.Manager) error {
	invs, err := invMgr.ListRecent(ctx, 5000)
	if err != nil {
		return fmt.Errorf("list local: %w", err)
	}
	for _, inv := range invs {
		var indicators []string
		m.PushInvestigation(ctx, "local", inv.ID, inv.Status, inv.Intent, inv.Playbook, "", inv.Confidence, indicators, "")
	}
	log.Printf("[server] synced %d local investigations", len(invs))
	return nil
}

func (m *ServerManager) updateCorrelation(ctx context.Context, ioc, nodeID string) {
	var existingIDs string
	var count int
	err := m.db.QueryRowContext(ctx,
		`SELECT node_ids, count FROM server_correlations WHERE ioc = ?`, ioc).
		Scan(&existingIDs, &count)
	if err != nil {
		now := time.Now().UTC().Format(time.RFC3339)
		nodes := "[\"" + nodeID + "\"]"
		m.db.ExecContext(ctx,
			`INSERT INTO server_correlations (id, ioc, node_ids, count, confidence, first_seen, last_seen) VALUES (?, ?, ?, 1, 0.5, ?, ?)`,
			uuid.New().String(), ioc, nodes, now, now)
		return
	}

	var nodes []string
	json.Unmarshal([]byte(existingIDs), &nodes)

	seen := false
	for _, n := range nodes {
		if n == nodeID {
			seen = true
			break
		}
	}
	if !seen {
		nodes = append(nodes, nodeID)
	}

	nodesJSON, _ := json.Marshal(nodes)
	newCount := len(nodes)
	confidence := 0.5
	if newCount >= 3 {
		confidence = 0.9
	} else if newCount >= 2 {
		confidence = 0.75
	}

	now := time.Now().UTC().Format(time.RFC3339)
	m.db.ExecContext(ctx,
		`UPDATE server_correlations SET node_ids = ?, count = ?, confidence = ?, last_seen = ? WHERE ioc = ?`,
		string(nodesJSON), newCount, confidence, now, ioc)
}

// orgPredicate returns a strict tenant predicate for ctx-bound scoping.
// Tenants match strict equality only; legacy unassigned rows (org_id=”)
// are invisible to tenants (fail-closed). Admin callers with empty org
// see rows across orgs. Every server list takes this predicate — the
// OR org_id=” fail-open pattern is gone.
func orgPredicate(ctx context.Context, args *[]any) string {
	org, _ := ctx.Value(ctxKeyOrg).(string)
	if org == "" {
		return ""
	}
	*args = append(*args, org)
	return " AND org_id = ?"
}

func (m *ServerManager) ListNodes(ctx context.Context, limit, offset int) ([]NodeInfo, int, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT id, hostname, version, status, COALESCE(last_heartbeat, ''), created_at FROM server_nodes WHERE 1=1`
	var args []any
	q += orgPredicate(ctx, &args)
	q += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []NodeInfo
	for rows.Next() {
		var n NodeInfo
		if err := rows.Scan(&n.ID, &n.Hostname, &n.Version, &n.Status, &n.LastSeen, &n.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	next := 0
	if len(out) > limit {
		out = out[:limit]
		next = offset + limit
	}
	return out, next, nil
}
func (m *ServerManager) ListInvestigations(ctx context.Context, limit, offset int, nodeID, statusFilter, search string) ([]ServerInvestigation, int, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT id, node_id, status, intent, COALESCE(playbook, ''), confidence,
		COALESCE(summary, ''), COALESCE(indicators, ''), COALESCE(report, ''), COALESCE(source_edge, ''),
		created_at, updated_at FROM server_investigations WHERE 1=1`
	var args []any
	q += orgPredicate(ctx, &args)

	if nodeID != "" {
		q += " AND node_id = ?"
		args = append(args, nodeID)
	}
	if statusFilter != "" {
		q += " AND status = ?"
		args = append(args, statusFilter)
	}
	if search != "" {
		if len(search) > maxSearchLen {
			search = search[:maxSearchLen]
		}
		q += " AND (intent LIKE ? OR id LIKE ? OR COALESCE(summary, '') LIKE ?)"
		s := "%" + search + "%"
		args = append(args, s, s, s)
	}
	q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit+1, offset)

	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ServerInvestigation
	for rows.Next() {
		var inv ServerInvestigation
		var indJSON, report string
		if err := rows.Scan(&inv.ID, &inv.NodeID, &inv.Status, &inv.Intent, &inv.Playbook,
			&inv.Confidence, &inv.Summary, &indJSON, &report, &inv.SourceEdge,
			&inv.CreatedAt, &inv.UpdatedAt); err != nil {
			return nil, 0, err
		}
		json.Unmarshal([]byte(indJSON), &inv.Indicators)
		inv.Report = report
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	next := 0
	if len(out) > limit {
		out = out[:limit]
		next = offset + limit
	}
	return out, next, nil
}

func (m *ServerManager) GetInvestigation(ctx context.Context, id string) (*ServerInvestigation, error) {
	if !validResourceID(id) {
		return nil, fmt.Errorf("invalid id")
	}
	var inv ServerInvestigation
	var indJSON, report string
	q := `SELECT id, node_id, status, intent, COALESCE(playbook, ''), confidence,
		COALESCE(summary, ''), COALESCE(indicators, ''), COALESCE(report, ''), COALESCE(source_edge, ''),
		created_at, updated_at FROM server_investigations WHERE id = ?`
	var args []any
	args = append(args, id)
	q += orgPredicate(ctx, &args)
	err := m.db.QueryRowContext(ctx, q, args...).
		Scan(&inv.ID, &inv.NodeID, &inv.Status, &inv.Intent, &inv.Playbook,
			&inv.Confidence, &inv.Summary, &indJSON, &report, &inv.SourceEdge,
			&inv.CreatedAt, &inv.UpdatedAt)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(indJSON), &inv.Indicators)
	inv.Report = report
	return &inv, nil
}

func (m *ServerManager) GetCorrelations(ctx context.Context, minCount int, limit, offset int) ([]map[string]any, int, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT ioc, node_ids, count, confidence, first_seen, last_seen FROM server_correlations WHERE count >= ?`
	args := []any{minCount}
	q += orgPredicate(ctx, &args)
	q += ` ORDER BY count DESC, confidence DESC LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var ioc, nodeIDs, firstSeen, lastSeen string
		var count int
		var confidence float64
		if err := rows.Scan(&ioc, &nodeIDs, &count, &confidence, &firstSeen, &lastSeen); err != nil {
			return nil, 0, err
		}
		out = append(out, map[string]any{
			"ioc":        ioc,
			"node_count": count,
			"confidence": confidence,
			"first_seen": firstSeen,
			"last_seen":  lastSeen,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	next := 0
	if len(out) > limit {
		out = out[:limit]
		next = offset + limit
	}
	return out, next, nil
}

func (m *ServerManager) SeedDefaultUser(ctx context.Context) (string, error) {
	var count int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_users`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	// Secure random 256-bit key (hex). Returned once: RunServer persists it
	// to a write-once 0600 file; the DB stores only the hash.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("seed default user: %w", err)
	}
	defaultKey := hex.EncodeToString(raw)
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO server_users (id, email, password_hash, role, api_key, api_key_hash, api_key_prefix, org_id, scope) VALUES (?, ?, ?, ?, '', ?, ?, '', 'full')`,
		uuid.New().String(), "admin@trace.local", "", "admin", hashSecret(defaultKey), defaultKey[:8]); err != nil {
		return "", fmt.Errorf("seed default user: %w", err)
	}
	log.Printf("[server] created default admin user")
	return defaultKey, nil
}

// validRoleName reports whether s is a known role.
func validRoleName(s string) bool { return validRole(s) }

func (m *ServerManager) CreateUser(ctx context.Context, email, apiKey, role, orgID string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("create user: email required")
	}
	if role == "" {
		role = string(RoleAnalyst)
	}
	if !validRoleName(role) {
		return "", fmt.Errorf("create user: unknown role %q", role)
	}
	if apiKey == "" {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return "", fmt.Errorf("create user: %w", err)
		}
		apiKey = hex.EncodeToString(raw)
	}
	prefix := apiKey
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	id := uuid.New().String()
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO server_users (id, email, password_hash, role, api_key, api_key_hash, api_key_prefix, org_id) VALUES (?, ?, ?, ?, '', ?, ?, ?)`,
		id, email, "", role, hashSecret(apiKey), prefix, orgID); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

func (m *ServerManager) RotateAPIKey(ctx context.Context, email string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	newKey := hex.EncodeToString(raw)
	prefix := newKey
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	res, err := m.db.ExecContext(ctx,
		`UPDATE server_users SET api_key_hash = ?, api_key_prefix = ?, api_key = '', api_key_expires_at = NULL WHERE email = ?`,
		hashSecret(newKey), prefix, email)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", sql.ErrNoRows
	}
	return newKey, nil
}

func (m *ServerManager) Authenticate(ctx context.Context, apiKey string) (string, string, error) {
	id, role, _, _, err := m.AuthenticateOrgFull(ctx, apiKey)
	return id, role, err
}

func (m *ServerManager) AuthenticateOrg(ctx context.Context, apiKey string) (string, string, string, error) {
	id, role, orgID, _, err := m.AuthenticateOrgFull(ctx, apiKey)
	return id, role, orgID, err
}

// AuthenticateOrgFull validates a header-presented user key against stored
// hashes, enforcing expiry. Returns (userID, role, orgID, scope).
func (m *ServerManager) AuthenticateOrgFull(ctx context.Context, apiKey string) (string, string, string, string, error) {
	if apiKey == "" || len(apiKey) > 512 {
		return "", "", "", "", status.Error(codes.Unauthenticated, "invalid api key")
	}
	var id, role, orgID, scope string
	var expires sql.NullString
	err := m.db.QueryRowContext(ctx,
		`SELECT id, role, COALESCE(org_id, ''), COALESCE(scope, 'full'), api_key_expires_at FROM server_users WHERE api_key_hash = ?`, hashSecret(apiKey)).
		Scan(&id, &role, &orgID, &scope, &expires)
	if err != nil {
		return "", "", "", "", status.Error(codes.Unauthenticated, "invalid api key")
	}
	if expires.Valid && expires.String != "" {
		if t, err := time.Parse(time.RFC3339, expires.String); err == nil && time.Now().UTC().After(t) {
			return "", "", "", "", status.Error(codes.Unauthenticated, "api key expired")
		}
	}
	if role == "" {
		role = string(RoleViewer)
	}
	if !validRoleName(role) {
		return "", "", "", "", status.Error(codes.Unauthenticated, "invalid api key")
	}
	return id, role, orgID, scope, nil
}

func (m *ServerManager) AuthenticateAgent(ctx context.Context, apiKey string) (string, string, error) {
	if apiKey == "" || len(apiKey) > 512 {
		return "", "", fmt.Errorf("invalid agent key")
	}
	var agentID, orgID string
	err := m.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(org_id, '') FROM edr_agents WHERE api_key_hash = ? AND status = 'active'`, hashSecret(apiKey)).Scan(&agentID, &orgID)
	if err != nil {
		return "", "", fmt.Errorf("invalid agent key")
	}
	return agentID, orgID, nil
}

var allowedComplianceFrameworks = map[string]bool{
	"pci_dss_v4.0": true, "pci_dss_v3.2.1": true, "hipaa": true, "gdpr": true,
	"nist_sp_800-53": true, "iso_27001-2013": true, "soc_2": true, "cis_csc_v8": true,
}

func (m *ServerManager) RecordComplianceSnapshot(ctx context.Context, orgID, hostname, framework string, score float64, total, passed, failed, notCovered int, snapshot []byte) error {
	if !allowedComplianceFrameworks[framework] {
		return fmt.Errorf("unknown framework %q", framework)
	}
	if score < 0 || score > 100 {
		return fmt.Errorf("score %.2f out of range [0,100]", score)
	}
	if total < 0 || passed < 0 || failed < 0 || notCovered < 0 {
		return fmt.Errorf("compliance counts must be non-negative")
	}
	if passed+failed+notCovered != total {
		return fmt.Errorf("compliance counts %d+%d+%d != total %d", passed, failed, notCovered, total)
	}
	if orgID == "" {
		if o, _ := ctx.Value(ctxKeyOrg).(string); o != "" {
			orgID = o
		}
	}
	// Snapshot payloads are stored verbatim; no hostname-shaped special case.
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO compliance_snapshots (id, hostname, framework, score, total, passed, failed, not_covered, org_id, snapshot, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		uuid.New().String(), hostname, framework, score, total, passed, failed, notCovered, orgID, string(snapshot))
	return err
}

type ComplianceScorePoint struct {
	Date   string  `json:"date"`
	Score  float64 `json:"score"`
	Total  int     `json:"total"`
	Passed int     `json:"passed"`
	Failed int     `json:"failed"`
}

func (m *ServerManager) GetComplianceHistory(ctx context.Context, hostname, framework string, days int) ([]ComplianceScorePoint, error) {
	if !allowedComplianceFrameworks[framework] {
		return nil, fmt.Errorf("unknown framework %q", framework)
	}
	if days <= 0 || days > 365 {
		days = 30
	}
	cutoff := fmt.Sprintf("-%d days", days)
	q := `SELECT created_at, score, total, passed, failed FROM compliance_snapshots
		 WHERE hostname = ? AND framework = ?
		 AND created_at >= datetime('now', ?)`
	args := []any{hostname, framework, cutoff}
	q += orgPredicate(ctx, &args)
	q += ` ORDER BY created_at LIMIT 500`
	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []ComplianceScorePoint
	for rows.Next() {
		var p ComplianceScorePoint
		if err := rows.Scan(&p.Date, &p.Score, &p.Total, &p.Passed, &p.Failed); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return points, nil
}

func (m *ServerManager) CreateOrg(ctx context.Context, name string) (string, error) {
	if strings.TrimSpace(name) == "" || len(name) > 128 {
		return "", fmt.Errorf("create org: name required")
	}
	id := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO server_orgs (id, name) VALUES (?, ?)`, id, strings.TrimSpace(name))
	if err != nil {
		return "", err
	}
	return id, nil
}
