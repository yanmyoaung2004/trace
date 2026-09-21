package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTenantIsolationTwoOrgs proves live two-org containment (FULLY_WORKING W0).
//
// Two orgs are created with an admin user + an enrolled agent each (agents via
// MintProvisionToken + enrollAgentTx, so org_id is server-assigned exactly as
// the provision-token enroll path assigns it). Cross-org reads must return
// 403/empty, and legacy '' rows must stay invisible to tenants.
func TestTenantIsolationTwoOrgs(t *testing.T) {
	mgr := newTestManager(t)
	if err := mgr.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()

	orgA, err := mgr.CreateOrg(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("CreateOrg A: %v", err)
	}
	orgB, err := mgr.CreateOrg(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("CreateOrg B: %v", err)
	}

	const keyA = "tenant-proof-user-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const keyB = "tenant-proof-user-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := mgr.CreateUser(ctx, "admin-a@trace.local", keyA, string(RoleAdmin), orgA); err != nil {
		t.Fatalf("CreateUser A: %v", err)
	}
	if _, err := mgr.CreateUser(ctx, "admin-b@trace.local", keyB, string(RoleAdmin), orgB); err != nil {
		t.Fatalf("CreateUser B: %v", err)
	}

	ctxA := context.WithValue(ctx, ctxKeyOrg, orgA)
	ctxB := context.WithValue(ctx, ctxKeyOrg, orgB)

	nodeA, err := mgr.RegisterNode(ctxA, "node-a", "1.0.0")
	if err != nil {
		t.Fatalf("RegisterNode A: %v", err)
	}
	nodeB, err := mgr.RegisterNode(ctxB, "node-b", "1.0.0")
	if err != nil {
		t.Fatalf("RegisterNode B: %v", err)
	}
	if err := mgr.PushInvestigation(ctxA, nodeA.ID, "inv-a-001", "open", "intent A", "", "summary A", nil, []string{"ioc-a"}, "report A"); err != nil {
		t.Fatalf("PushInvestigation A: %v", err)
	}
	if err := mgr.PushInvestigation(ctxB, nodeB.ID, "inv-b-001", "open", "intent B", "", "summary B", nil, []string{"ioc-b"}, "report B"); err != nil {
		t.Fatalf("PushInvestigation B: %v", err)
	}

	tokA, err := mgr.MintProvisionToken(ctx, orgA, "fleet-a", time.Hour)
	if err != nil {
		t.Fatalf("MintProvisionToken A: %v", err)
	}
	tokB, err := mgr.MintProvisionToken(ctx, orgB, "fleet-b", time.Hour)
	if err != nil {
		t.Fatalf("MintProvisionToken B: %v", err)
	}
	agentA, agentKeyA, err := mgr.enrollAgentTx(ctx, orgA, "agent-a", "linux", "amd64", "1.0.0", "1.0.0", "6.8.0", "default", 4, "TestCPU", 8192, "10.0.0.11")
	if err != nil {
		t.Fatalf("enrollAgentTx A: %v", err)
	}
	agentB, agentKeyB, err := mgr.enrollAgentTx(ctx, orgB, "agent-b", "linux", "amd64", "1.0.0", "1.0.0", "6.8.0", "default", 4, "TestCPU", 8192, "10.0.0.12")
	if err != nil {
		t.Fatalf("enrollAgentTx B: %v", err)
	}
	_ = tokA
	_ = tokB

	mux := http.NewServeMux()
	sync := NewSyncHandler(mgr)
	sync.RegisterRoutes(mux)

	do := func(method, path, key, body string) *httptest.ResponseRecorder {
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// Each agent posts one event under its own ctx-bound identity.
	if rec := do("POST", "/api/v1/edr/events", agentKeyA, `{"events":[{"type":"process.start","severity":5}]}`); rec.Code != http.StatusOK {
		t.Fatalf("seed event A: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do("POST", "/api/v1/edr/events", agentKeyB, `{"events":[{"type":"file.write","severity":4}]}`); rec.Code != http.StatusOK {
		t.Fatalf("seed event B: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Legacy pre-tenancy rows (org_id='') must stay invisible to tenants.
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := mgr.db.ExecContext(ctx,
		`INSERT INTO server_nodes (id, hostname, version, status, org_id, last_heartbeat, created_at) VALUES (?, ?, ?, 'active', '', ?, ?)`,
		"legacy-node-1", "legacy-node", "0.0.0", now, now); err != nil {
		t.Fatalf("legacy node: %v", err)
	}
	if _, err := mgr.db.ExecContext(ctx,
		`INSERT INTO server_investigations (id, node_id, status, intent, org_id, created_at, updated_at) VALUES (?, ?, 'open', 'legacy', '', ?, ?)`,
		"legacy-inv-1", "legacy-node-1", now, now); err != nil {
		t.Fatalf("legacy investigation: %v", err)
	}
	if _, err := mgr.db.ExecContext(ctx,
		`INSERT INTO edr_agents (id, hostname, platform, arch, version, agent_version, status, org_id, last_heartbeat, created_at, updated_at)
		 VALUES (?, 'legacy-agent', 'linux', 'amd64', '0.0.0', '0.0.0', 'active', '', ?, ?, ?)`,
		"legacy-agent-1", now, now, now); err != nil {
		t.Fatalf("legacy agent: %v", err)
	}
	if _, err := mgr.db.ExecContext(ctx,
		`INSERT INTO edr_events (id, agent_id, event_type, severity, data, org_id, timestamp) VALUES (?, ?, 'legacy.evt', 1, '{}', '', ?)`,
		"legacy-event-1", "legacy-agent-1", now); err != nil {
		t.Fatalf("legacy event: %v", err)
	}
	if _, err := mgr.db.ExecContext(ctx,
		`INSERT INTO edr_actions (id, agent_id, action_type, params, status, org_id) VALUES (?, ?, 'system_snapshot', '{}', 'pending', '')`,
		"legacy-action-1", "legacy-agent-1"); err != nil {
		t.Fatalf("legacy action: %v", err)
	}

	// listIDs pulls the "id" values out of a named array inside the envelope
	// data payload (nodes/investigations use "items", agents use "agents").
	listIDs := func(t *testing.T, rec *httptest.ResponseRecorder, field string) []string {
		t.Helper()
		var env struct {
			Data  map[string]json.RawMessage `json:"data"`
			Error string                     `json:"error"`
			Code  int                        `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		var arr []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(env.Data[field], &arr); err != nil {
			t.Fatalf("unmarshal %q: %v", field, err)
		}
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			out = append(out, e.ID)
		}
		return out
	}
	contains := func(ids []string, want string) bool {
		for _, id := range ids {
			if id == want {
				return true
			}
		}
		return false
	}

	t.Run("nodes isolated, legacy invisible", func(t *testing.T) {
		rec := do("GET", "/api/v1/nodes", keyA, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("nodes A: status=%d", rec.Code)
		}
		ids := listIDs(t, rec, "items")
		if !contains(ids, nodeA.ID) {
			t.Errorf("tenant A missing own node %s (got %v)", nodeA.ID, ids)
		}
		if contains(ids, nodeB.ID) {
			t.Errorf("tenant A sees tenant B node %s", nodeB.ID)
		}
		if contains(ids, "legacy-node-1") {
			t.Error("tenant A sees legacy '' node")
		}

		rec = do("GET", "/api/v1/nodes", keyB, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("nodes B: status=%d", rec.Code)
		}
		ids = listIDs(t, rec, "items")
		if !contains(ids, nodeB.ID) {
			t.Errorf("tenant B missing own node %s (got %v)", nodeB.ID, ids)
		}
		if contains(ids, nodeA.ID) {
			t.Errorf("tenant B sees tenant A node %s", nodeA.ID)
		}
		if contains(ids, "legacy-node-1") {
			t.Error("tenant B sees legacy '' node")
		}
	})

	t.Run("investigations isolated, legacy invisible", func(t *testing.T) {
		rec := do("GET", "/api/v1/investigations", keyA, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("investigations A: status=%d", rec.Code)
		}
		ids := listIDs(t, rec, "items")
		if !contains(ids, "inv-a-001") || contains(ids, "inv-b-001") || contains(ids, "legacy-inv-1") {
			t.Errorf("tenant A list wrong: %v", ids)
		}

		rec = do("GET", "/api/v1/investigations", keyB, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("investigations B: status=%d", rec.Code)
		}
		ids = listIDs(t, rec, "items")
		if !contains(ids, "inv-b-001") || contains(ids, "inv-a-001") || contains(ids, "legacy-inv-1") {
			t.Errorf("tenant B list wrong: %v", ids)
		}

		if rec := do("GET", "/api/v1/investigations/inv-a-001", keyA, ""); rec.Code != http.StatusOK {
			t.Errorf("own investigation: status=%d, want 200", rec.Code)
		}
		if rec := do("GET", "/api/v1/investigations/inv-b-001", keyA, ""); rec.Code != http.StatusNotFound {
			t.Errorf("cross-org investigation: status=%d, want 404", rec.Code)
		}
		if rec := do("GET", "/api/v1/investigations/inv-a-001", keyB, ""); rec.Code != http.StatusNotFound {
			t.Errorf("cross-org investigation (mirrored): status=%d, want 404", rec.Code)
		}
		if rec := do("GET", "/api/v1/investigations/legacy-inv-1", keyA, ""); rec.Code != http.StatusNotFound {
			t.Errorf("legacy investigation: status=%d, want 404", rec.Code)
		}
	})

	t.Run("agents isolated, legacy invisible", func(t *testing.T) {
		rec := do("GET", "/api/v1/edr/agents", keyA, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("agents A: status=%d", rec.Code)
		}
		ids := listIDs(t, rec, "agents")
		if !contains(ids, agentA) || contains(ids, agentB) || contains(ids, "legacy-agent-1") {
			t.Errorf("tenant A agents wrong: %v", ids)
		}

		rec = do("GET", "/api/v1/edr/agents", keyB, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("agents B: status=%d", rec.Code)
		}
		ids = listIDs(t, rec, "agents")
		if !contains(ids, agentB) || contains(ids, agentA) || contains(ids, "legacy-agent-1") {
			t.Errorf("tenant B agents wrong: %v", ids)
		}

		if rec := do("GET", "/api/v1/edr/agents/"+agentA, keyA, ""); rec.Code != http.StatusOK {
			t.Errorf("own agent: status=%d, want 200", rec.Code)
		}
		if rec := do("GET", "/api/v1/edr/agents/"+agentB, keyA, ""); rec.Code != http.StatusNotFound {
			t.Errorf("cross-org agent: status=%d, want 404", rec.Code)
		}
		if rec := do("GET", "/api/v1/edr/agents/legacy-agent-1", keyA, ""); rec.Code != http.StatusNotFound {
			t.Errorf("legacy agent: status=%d, want 404", rec.Code)
		}
		// Cross-org revoke is 403 and mutates nothing.
		if rec := do("DELETE", "/api/v1/edr/agents/"+agentB, keyA, ""); rec.Code != http.StatusForbidden {
			t.Errorf("cross-org revoke: status=%d, want 403", rec.Code)
		}
		var status string
		if err := mgr.db.QueryRowContext(ctx, `SELECT status FROM edr_agents WHERE id = ?`, agentB).Scan(&status); err != nil || status != "active" {
			t.Errorf("cross-org revoke mutated agent B: status=%q err=%v", status, err)
		}
	})

	t.Run("events isolated, legacy contained", func(t *testing.T) {
		rec := do("GET", "/api/v1/edr/events?agent_id="+agentA, keyA, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("own events: status=%d body=%s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Events []json.RawMessage `json:"events"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal events: %v", err)
		}
		if len(env.Data.Events) == 0 {
			t.Error("own events: empty, want >= 1 seeded event")
		}

		if rec := do("GET", "/api/v1/edr/events?agent_id="+agentB, keyA, ""); rec.Code != http.StatusForbidden {
			t.Errorf("cross-org events: status=%d, want 403", rec.Code)
		}
		if rec := do("GET", "/api/v1/edr/events?agent_id="+agentA, keyB, ""); rec.Code != http.StatusForbidden {
			t.Errorf("cross-org events (mirrored): status=%d, want 403", rec.Code)
		}
		if rec := do("GET", "/api/v1/edr/events?agent_id=legacy-agent-1", keyA, ""); rec.Code != http.StatusForbidden {
			t.Errorf("legacy events: status=%d, want 403", rec.Code)
		}
	})

	t.Run("actions isolated", func(t *testing.T) {
		// Cross-org dispatch is 403.
		if rec := do("POST", "/api/v1/edr/actions/dispatch", keyA,
			`{"agent_id":"`+agentB+`","action_type":"system_snapshot"}`); rec.Code != http.StatusForbidden {
			t.Errorf("cross-org dispatch: status=%d, want 403", rec.Code)
		}
		if rec := do("POST", "/api/v1/edr/actions/dispatch", keyA,
			`{"agent_id":"legacy-agent-1","action_type":"system_snapshot"}`); rec.Code != http.StatusForbidden {
			t.Errorf("legacy dispatch: status=%d, want 403", rec.Code)
		}
		// Own dispatch succeeds; results are ctx-bound to the target agent.
		rec := do("POST", "/api/v1/edr/actions/dispatch", keyA,
			`{"agent_id":"`+agentA+`","action_type":"system_snapshot"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("own dispatch: status=%d body=%s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				ActionID string `json:"action_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Data.ActionID == "" {
			t.Fatalf("dispatch action_id: %v body=%s", err, rec.Body.String())
		}
		resultBody := `{"action_id":"` + env.Data.ActionID + `","status":"completed","executed_at":"` + now + `"}`
		if rec := do("POST", "/api/v1/edr/actions/result", agentKeyB, resultBody); rec.Code != http.StatusNotFound {
			t.Errorf("cross-agent result: status=%d, want 404", rec.Code)
		}
		if rec := do("POST", "/api/v1/edr/actions/result", agentKeyA, resultBody); rec.Code != http.StatusOK {
			t.Errorf("own result: status=%d, want 200", rec.Code)
		}
	})

	t.Run("register ignores client org_id", func(t *testing.T) {
		spoofTok, err := mgr.MintProvisionToken(ctx, orgA, "spoof", time.Hour)
		if err != nil {
			t.Fatalf("MintProvisionToken spoof: %v", err)
		}
		rec := do("POST", "/api/v1/edr/register", "",
			`{"hostname":"spoof-agent","platform":"linux","arch":"amd64","version":"1.0.0","provision_token":"`+spoofTok+`","org_id":"`+orgB+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("spoof register: status=%d body=%s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				AgentID string `json:"agent_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Data.AgentID == "" {
			t.Fatalf("register agent_id: %v body=%s", err, rec.Body.String())
		}
		// Server-assigned to the token's org (A): visible to A, 404 to B.
		if rec := do("GET", "/api/v1/edr/agents/"+env.Data.AgentID, keyB, ""); rec.Code != http.StatusNotFound {
			t.Errorf("spoofed agent visible to B: status=%d, want 404", rec.Code)
		}
		if rec := do("GET", "/api/v1/edr/agents/"+env.Data.AgentID, keyA, ""); rec.Code != http.StatusOK {
			t.Errorf("spoofed agent hidden from A: status=%d, want 200", rec.Code)
		}
	})
}
