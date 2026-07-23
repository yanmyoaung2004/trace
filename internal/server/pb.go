package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	Status      string    `json:"status"`
	Intent      string    `json:"intent"`
	Playbook    string    `json:"playbook,omitempty"`
	Confidence  *float64  `json:"confidence,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Indicators  []string  `json:"indicators,omitempty"`
	Report      string    `json:"report,omitempty"`
	SourceEdge  string    `json:"source_edge,omitempty"`
	CreatedAt   string    `json:"created_at"`
	UpdatedAt   string    `json:"updated_at"`
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
			last_heartbeat TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
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
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_node ON server_investigations(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_status ON server_investigations(status)`,
		`CREATE INDEX IF NOT EXISTS idx_server_inv_created ON server_investigations(created_at)`,
		`CREATE TABLE IF NOT EXISTS server_users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'analyst',
			api_key TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS server_correlations (
			id TEXT PRIMARY KEY,
			ioc TEXT NOT NULL,
			node_ids TEXT NOT NULL,
			count INTEGER NOT NULL DEFAULT 1,
			confidence REAL DEFAULT 0.5,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_corr_ioc ON server_correlations(ioc)`,
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
			api_key_hash TEXT,
			last_heartbeat TEXT,
			last_ip TEXT,
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS edr_events (
			id TEXT PRIMARY KEY,
			agent_id TEXT NOT NULL REFERENCES edr_agents(id),
			event_type TEXT NOT NULL,
			severity INTEGER NOT NULL DEFAULT 1,
			data TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_agent ON edr_events(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_type ON edr_events(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_severity ON edr_events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_events_time ON edr_events(timestamp)`,
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
			org_id TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_actions_agent ON edr_actions(agent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_edr_actions_status ON edr_actions(status)`,
		`CREATE TABLE IF NOT EXISTS edr_fp_counters (
			rule_name TEXT NOT NULL,
			process_name TEXT NOT NULL,
			dismissals INTEGER NOT NULL DEFAULT 1,
			throttled INTEGER NOT NULL DEFAULT 0,
			org_id TEXT DEFAULT '',
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
			snapshot TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cs_host ON compliance_snapshots(hostname)`,
		`CREATE INDEX IF NOT EXISTS idx_cs_framework ON compliance_snapshots(framework)`,
		`CREATE TABLE IF NOT EXISTS server_orgs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
	}

	for _, q := range queries {
		if _, err := m.db.Exec(q); err != nil {
			return fmt.Errorf("server migrate: %w", err)
		}
	}

	// Migration: add cpu_name if missing (ignore error if column already exists)
	m.db.Exec("ALTER TABLE edr_agents ADD COLUMN cpu_name TEXT DEFAULT ''")

	// Migration: add org_id columns for RBAC
	m.db.Exec("ALTER TABLE server_users ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE edr_agents ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE edr_events ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE server_nodes ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE server_investigations ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE server_correlations ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE edr_actions ADD COLUMN org_id TEXT DEFAULT ''")
	m.db.Exec("ALTER TABLE edr_fp_counters ADD COLUMN org_id TEXT DEFAULT ''")

	return nil
}

func (m *ServerManager) RegisterNode(ctx context.Context, hostname, version string) (*NodeInfo, error) {
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := m.db.ExecContext(ctx,
		`INSERT INTO server_nodes (id, hostname, version, status, last_heartbeat, created_at) VALUES (?, ?, ?, 'active', ?, ?)`,
		id, hostname, version, now, now)
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
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := m.db.ExecContext(ctx,
		`UPDATE server_nodes SET last_heartbeat = ?, status = 'active' WHERE id = ?`, now, nodeID)
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
	now := time.Now().UTC().Format(time.RFC3339)
	indJSON, _ := json.Marshal(indicators)

	_, err := m.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO server_investigations
		 (id, node_id, status, intent, playbook, confidence, summary, indicators, report, source_edge, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM server_investigations WHERE id = ?), ?), ?)`,
		invID, nodeID, statusStr, intent, playbook, confidence, summary, string(indJSON), report, nodeID, invID, now, now)
	if err != nil {
		return fmt.Errorf("push investigation: %w", err)
	}

	for _, ioc := range indicators {
		if ioc == "" {
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

func (m *ServerManager) ListNodes(ctx context.Context) ([]NodeInfo, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, hostname, version, status, COALESCE(last_heartbeat, ''), created_at FROM server_nodes ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []NodeInfo
	for rows.Next() {
		var n NodeInfo
		if err := rows.Scan(&n.ID, &n.Hostname, &n.Version, &n.Status, &n.LastSeen, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (m *ServerManager) ListInvestigations(ctx context.Context, limit int, nodeID, statusFilter, search string) ([]ServerInvestigation, error) {
	q := `SELECT id, node_id, status, intent, COALESCE(playbook, ''), confidence,
		COALESCE(summary, ''), COALESCE(indicators, ''), COALESCE(report, ''), COALESCE(source_edge, ''),
		created_at, updated_at FROM server_investigations WHERE 1=1`
	var args []any

	if nodeID != "" {
		q += " AND node_id = ?"
		args = append(args, nodeID)
	}
	if statusFilter != "" {
		q += " AND status = ?"
		args = append(args, statusFilter)
	}
	if search != "" {
		q += " AND (intent LIKE ? OR id LIKE ? OR COALESCE(summary, '') LIKE ?)"
		s := "%" + search + "%"
		args = append(args, s, s, s)
	}
	q += " ORDER BY created_at DESC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	} else {
		q += " LIMIT 100"
	}

	rows, err := m.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ServerInvestigation
	for rows.Next() {
		var inv ServerInvestigation
		var indJSON, report string
		if err := rows.Scan(&inv.ID, &inv.NodeID, &inv.Status, &inv.Intent, &inv.Playbook,
			&inv.Confidence, &inv.Summary, &indJSON, &report, &inv.SourceEdge,
			&inv.CreatedAt, &inv.UpdatedAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(indJSON), &inv.Indicators)
		inv.Report = report
		out = append(out, inv)
	}
	return out, nil
}

func (m *ServerManager) GetInvestigation(ctx context.Context, id string) (*ServerInvestigation, error) {
	var inv ServerInvestigation
	var indJSON, report string
	err := m.db.QueryRowContext(ctx,
		`SELECT id, node_id, status, intent, COALESCE(playbook, ''), confidence,
		COALESCE(summary, ''), COALESCE(indicators, ''), COALESCE(report, ''), COALESCE(source_edge, ''),
		created_at, updated_at FROM server_investigations WHERE id = ?`, id).
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

func (m *ServerManager) GetCorrelations(ctx context.Context, minCount int) ([]map[string]any, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT ioc, node_ids, count, confidence, first_seen, last_seen FROM server_correlations WHERE count >= ? ORDER BY count DESC, confidence DESC LIMIT 100`,
		minCount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var ioc, nodeIDs, firstSeen, lastSeen string
		var count int
		var confidence float64
		if err := rows.Scan(&ioc, &nodeIDs, &count, &confidence, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"ioc":        ioc,
			"node_count": count,
			"confidence": confidence,
			"first_seen": firstSeen,
			"last_seen":  lastSeen,
		})
	}
	return out, nil
}


func (m *ServerManager) SeedDefaultUser(ctx context.Context) (string, error) {
	var count int
	m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_users`).Scan(&count)
	if count == 0 {
		defaultKey := uuid.New().String()[:24]
		_, err := m.db.ExecContext(ctx,
			`INSERT INTO server_users (id, email, password_hash, role, api_key) VALUES (?, ?, ?, ?, ?)`,
			uuid.New().String(), "admin@trace.local", "", "admin", defaultKey)
		if err != nil {
			return "", fmt.Errorf("seed default user: %w", err)
		}
		log.Printf("[server] created default admin user")
		return defaultKey, nil
	}
	return "", nil
}

func (m *ServerManager) CreateUser(ctx context.Context, email, apiKey, role, orgID string) (string, error) {
	id := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO server_users (id, email, password_hash, role, api_key, org_id) VALUES (?, ?, ?, ?, ?, ?)`,
		id, email, "", role, apiKey, orgID)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

func (m *ServerManager) RotateAPIKey(ctx context.Context, email string) (string, error) {
	newKey := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`UPDATE server_users SET api_key = ? WHERE email = ?`, newKey, email)
	if err != nil {
		return "", err
	}
	return newKey, nil
}

func (m *ServerManager) Authenticate(ctx context.Context, apiKey string) (string, string, error) {
	var id, role string
	err := m.db.QueryRowContext(ctx,
		`SELECT id, role FROM server_users WHERE api_key = ?`, apiKey).
		Scan(&id, &role)
	if err != nil {
		return "", "", status.Error(codes.Unauthenticated, "invalid api key")
	}
	return id, role, nil
}

func (m *ServerManager) AuthenticateOrg(ctx context.Context, apiKey string) (string, string, string, error) {
	var id, role, orgID string
	err := m.db.QueryRowContext(ctx,
		`SELECT id, role, COALESCE(org_id, '') FROM server_users WHERE api_key = ?`, apiKey).
		Scan(&id, &role, &orgID)
	if err != nil {
		return "", "", "", status.Error(codes.Unauthenticated, "invalid api key")
	}
	return id, role, orgID, nil
}

func (m *ServerManager) AuthenticateAgent(ctx context.Context, apiKey string) (string, error) {
	h := sha256.Sum256([]byte(apiKey))
	hash := hex.EncodeToString(h[:])
	var agentID string
	err := m.db.QueryRowContext(ctx,
		`SELECT id FROM edr_agents WHERE api_key_hash = ? AND status = 'active'`, hash).Scan(&agentID)
	if err != nil {
		return "", fmt.Errorf("invalid agent key")
	}
	return agentID, nil
}

func (m *ServerManager) RecordComplianceSnapshot(ctx context.Context, hostname, framework string, score float64, total, passed, failed, notCovered int, snapshot []byte) error {
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO compliance_snapshots (id, hostname, framework, score, total, passed, failed, not_covered, snapshot, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		uuid.New().String(), hostname, framework, score, total, passed, failed, notCovered, string(snapshot))
	return err
}

type ComplianceScorePoint struct {
	Date      string  `json:"date"`
	Score     float64 `json:"score"`
	Total     int     `json:"total"`
	Passed    int     `json:"passed"`
	Failed    int     `json:"failed"`
}

func (m *ServerManager) GetComplianceHistory(ctx context.Context, hostname, framework string, days int) ([]ComplianceScorePoint, error) {
	cutoff := fmt.Sprintf("-%d days", days)
	rows, err := m.db.QueryContext(ctx,
		`SELECT created_at, score, total, passed, failed FROM compliance_snapshots
		 WHERE hostname = ? AND framework = ?
		 AND created_at >= datetime('now', ?)
		 ORDER BY created_at`, hostname, framework, cutoff)
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
	return points, nil
}

func (m *ServerManager) CreateOrg(ctx context.Context, name string) (string, error) {
	id := uuid.New().String()
	_, err := m.db.ExecContext(ctx,
		`INSERT INTO server_orgs (id, name) VALUES (?, ?)`, id, name)
	if err != nil {
		return "", err
	}
	return id, nil
}

func init() {
	_ = context.Background
	_ = json.Marshal
}
