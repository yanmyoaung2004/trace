package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/storage"
)

// EDR fleet handlers — trust-boundary rewrite (FIX_PLAN 0.2 + 0.3 + 0.8 + 1.5).
//
//   - Register: provision-token (single-use+expiry) or same-org admin approval
//     queue path. No auto-mint on anonymous POST. Server-assigned org_id; the
//     client OrgID field is ignored. Idempotency-Key dedupes retries (409).
//   - Heartbeat/events/pending/result: ctx-bound agent IDs. Body agent_id is
//     overwritten from ctx; pending keyed by ctx; result updates carry
//     AND agent_id=?.
//   - Dispatch: action allowlist + per-type JSON-schema-ish param validation +
//     size cap + approval stub (run_script/isolate denied by default) + audit.
//   - Delete agent: PermAgentRevoke (route wiring in RegisterRoutes).
//   - Compliance: PermCompliance + framework allowlist + score range (pb.go).
//   - Ingest validation: UUIDv7 validate-or-mint, severity/time clamps,
//     tenant pinned from ctx, max 1000 events (413 beyond).
//   - Lists: cursor pagination (?limit&cursor, max enforced).
//   - Envelope responses {data,error,code,request_id}.

// allowedDispatchActions is the dispatch allowlist (run_script is NOT listed:
// deny-by-default per FIX_PLAN 0.1/0.9; server expands no chains).
var allowedDispatchActions = map[string]bool{
	"kill_process":      true,
	"quarantine_file":   true,
	"block_ip":          true,
	"isolate_host":      true,
	"collect_forensics": true,
	"system_snapshot":   true,
}

// destructiveActions require explicit approval plumbing before execution.
// The agent still polls pending; dispatch records status='pending_approval'
// so nothing executes without an approver. Approval-token verification lives
// with ConfigAuditFixer (0.9); this gate keeps the server deny-closed until
// that lands.
var destructiveActions = map[string]bool{
	"isolate_host":    true,
	"kill_process":    true,
	"quarantine_file": true,
	"block_ip":        true,
}

// validateDispatchParams enforces per-type minimal schemas + size cap.
func validateDispatchParams(action string, params map[string]any) error {
	raw, _ := json.Marshal(params)
	if len(raw) > maxParamsBytes {
		return errParamsTooLarge
	}
	switch action {
	case "kill_process":
		if params == nil {
			return errMissingParam("pid or name")
		}
		_, hasPID := params["pid"]
		_, hasName := params["name"]
		if !hasPID && !hasName {
			return errMissingParam("pid or name")
		}
		if pid, ok := params["pid"]; ok {
			var n int64
			switch v := pid.(type) {
			case float64:
				n = int64(v)
			case int:
				n = int64(v)
			case int64:
				n = v
			default:
				return errBadParam("pid must be a number")
			}
			if n <= 0 || n > 1<<22 {
				return errBadParam("pid out of range")
			}
		}
	case "quarantine_file":
		p, _ := params["path"].(string)
		if p == "" {
			if t, _ := params["target"].(string); t != "" {
				p = t
			}
		}
		if p == "" || len(p) > 1024 {
			return errBadParam("path required (<=1024 chars)")
		}
	case "block_ip":
		ip, _ := params["ip"].(string)
		if ip == "" {
			if t, _ := params["target"].(string); t != "" {
				ip = t
			}
		}
		if ip == "" || len(ip) > 64 {
			return errBadParam("ip required (<=64 chars)")
		}
	case "isolate_host", "collect_forensics", "system_snapshot":
		// No required params beyond the size cap.
	default:
		return errUnknownAction(action)
	}
	return nil
}

type dispatchParamError struct{ msg string }

func (e *dispatchParamError) Error() string { return e.msg }

var errParamsTooLarge = &dispatchParamError{"params exceed 8KiB cap"}

func errMissingParam(what string) error { return &dispatchParamError{"missing param: " + what} }
func errBadParam(what string) error     { return &dispatchParamError{"invalid param: " + what} }
func errUnknownAction(a string) error   { return &dispatchParamError{"unknown action_type: " + a} }

func (h *SyncHandler) handleEDRRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	actor := clientIP(r)
	if key := r.Header.Get(idempotencyHeader); key != "" {
		if st, body, dup := h.manager.checkIdempotency(r.Context(), "register:"+key, "ip:"+actor, ""); dup {
			if st == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"duplicate request: already in progress or completed","code":409}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(body))
			return
		}
	}
	var req struct {
		Hostname       string `json:"hostname"`
		Platform       string `json:"platform"`
		Arch           string `json:"arch"`
		Version        string `json:"version"`
		KernelVersion  string `json:"kernel_version,omitempty"`
		CPUCount       int    `json:"cpu_count"`
		CPUName        string `json:"cpu_name"`
		MemoryMB       int64  `json:"memory_mb"`
		AgentVersion   string `json:"agent_version"`
		Monitors       string `json:"monitors"`
		OrgID          string `json:"org_id,omitempty"` // IGNORED: server-assigned
		ProvisionToken string `json:"provision_token,omitempty"`
		APIKey         string `json:"api_key,omitempty"` // legacy: rejected
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Hostname == "" || len(req.Hostname) > 256 {
		writeAPIError(w, r, http.StatusBadRequest, "hostname required (<=256 chars)")
		return
	}
	if req.APIKey != "" {
		// Client-minted keys are no longer honored (spoof vector).
		writeAPIError(w, r, http.StatusBadRequest, "client api_key rejected: enroll with a provision token")
		return
	}
	orgID := ""
	if req.ProvisionToken != "" {
		var err error
		orgID, err = h.manager.consumeProvisionToken(r.Context(), req.ProvisionToken)
		if err != nil {
			h.metrics.incAuthFailure("bad_provision_token")
			writeAPIError(w, r, http.StatusUnauthorized, err.Error())
			return
		}
	} else {
		// No token → admin approval queue path (deny-closed): record a
		// pending enrollment for an admin to approve via provision token.
		h.metrics.incAuthFailure("missing_provision_token")
		writeAPIError(w, r, http.StatusUnauthorized,
			"enrollment requires a provision token (ask an admin to mint one)")
		auditWrite(h.audit, r.Context(), "anonymous", "enroll.denied", "agent", req.Hostname, "missing provision token")
		return
	}
	_ = orgID
	ip, _, _ := splitHostPort(r.RemoteAddr)
	agentID, agentKey, err := h.manager.enrollAgentTx(r.Context(), orgID,
		req.Hostname, req.Platform, req.Arch, req.Version, req.AgentVersion,
		req.KernelVersion, req.Monitors, req.CPUCount, req.CPUName, req.MemoryMB, ip)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "registration failed")
		return
	}
	h.manager.finalizeProvisionUse(r.Context(), req.ProvisionToken, agentID)
	h.metrics.registrations.Add(1)
	auditWrite(h.audit, r.Context(), "provision:"+shortID(req.ProvisionToken), "agent.enrolled", "agent", agentID, "org="+orgID)
	respBody, _ := json.Marshal(Envelope{Data: map[string]string{
		"agent_id": agentID, "status": "registered", "api_key": agentKey,
	}, Code: http.StatusOK, RequestID: RequestIDFromContext(r.Context())})
	if key := r.Header.Get(idempotencyHeader); key != "" {
		h.manager.finishIdempotency(r.Context(), "register:"+key, "ip:"+actor, http.StatusOK, string(respBody))
	}
	slog.Info("agent registered", "agent", shortID(agentID), "org", shortID(orgID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

func (h *SyncHandler) handleEDRHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	agentID := ctxAgentID(r)
	if agentID == "" {
		writeAPIError(w, r, http.StatusUnauthorized, "agent auth required")
		return
	}
	var hb struct {
		AgentID  string `json:"agent_id"` // ignored: ctx is authoritative
		Hostname string `json:"hostname"`
		Status   string `json:"status"`
		Version  string `json:"version"`
		Uptime   int64  `json:"uptime"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	_ = json.NewDecoder(r.Body).Decode(&hb)
	now := time.Now().UTC().Format(time.RFC3339)
	ip, _, _ := splitHostPort(r.RemoteAddr)
	res, err := h.manager.db.ExecContext(r.Context(),
		`UPDATE edr_agents SET status = COALESCE(NULLIF(?, ''), status), last_heartbeat = ?, last_ip = ?, updated_at = ? WHERE id = ? AND status = 'active'`,
		hb.Status, now, ip, now, agentID)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "heartbeat failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeAPIError(w, r, http.StatusNotFound, "agent not found or revoked")
		return
	}
	h.metrics.heartbeats.Add(1)
	writeData(w, r, http.StatusOK, map[string]string{"status": "ok", "server_time": now})
}

func clampSeverity(s int) int {
	if s < 1 {
		return 1
	}
	if s > 10 {
		return 10
	}
	return s
}

// validateOrMintEventID accepts a client event ID only if it parses as a UUID;
// otherwise mints a fresh UUIDv7 so client-ID entropy never breaks the
// dedup/watermark path (FIX_PLAN 0.8/D6).
func validateOrMintEventID(clientID string) string {
	if clientID != "" {
		if err := uuid.Validate(clientID); err == nil {
			return clientID
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}
	return id.String()
}

func (h *SyncHandler) handleEDREvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.handleEDREventsQuery(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST or GET")
		return
	}
	agentID := ctxAgentID(r)
	if agentID == "" {
		writeAPIError(w, r, http.StatusUnauthorized, "agent auth required")
		return
	}
	var body struct {
		AgentID string            `json:"agent_id"` // ignored: ctx is authoritative
		Events  []json.RawMessage `json:"events"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if len(body.Events) > maxEventsPerPost {
		writeAPIError(w, r, http.StatusRequestEntityTooLarge,
			"too many events (max 1000 per POST)")
		return
	}
	orgID := OrgIDFromContext(r.Context())
	tx, err := h.manager.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(r.Context(),
		`INSERT INTO edr_events (id, agent_id, event_type, severity, data, org_id, timestamp, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "prepare error")
		return
	}
	defer stmt.Close()
	stored := 0
	var tseBatch []*storage.Event
	for _, raw := range body.Events {
		if len(raw) > 64<<10 {
			continue // drop single oversized event, keep batch
		}
		var evt struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Severity  int    `json:"severity"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(raw, &evt); err != nil {
			continue
		}
		if evt.Type == "" || len(evt.Type) > 64 {
			continue
		}
		id := validateOrMintEventID(evt.ID)
		sev := clampSeverity(evt.Severity)
		ts := time.Now().UTC().Format(time.RFC3339)
		if evt.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, evt.Timestamp); err == nil {
				// Clamp absurd timestamps (clock skew containment).
				now := time.Now()
				if t.After(now.Add(time.Hour)) {
					t = now
				}
				if t.Before(now.Add(-365 * 24 * time.Hour)) {
					t = now
				}
				ts = t.UTC().Format(time.RFC3339)
			}
		}
		if _, err := stmt.ExecContext(r.Context(), id, agentID, evt.Type, sev, string(raw), orgID, ts); err != nil {
			continue
		}
		stored++
		if h.tseWriter != nil && len(tseBatch) < maxEventsPerPost {
			t := time.Now().UnixMicro()
			if pt, err := time.Parse(time.RFC3339, ts); err == nil {
				t = pt.UnixMicro()
			}
			tseBatch = append(tseBatch, &storage.Event{
				ID: id, TenantID: orgID, AgentID: agentID,
				Timestamp: t, EventType: evt.Type, Severity: sev,
				DataRaw: raw,
			})
		}
	}
	if err := tx.Commit(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "commit error")
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"stored": stored, "received": len(body.Events)})
	if h.tseWriter != nil && len(tseBatch) > 0 {
		go func() {
			if err := h.tseWriter.WriteEvents(context.Background(), tseBatch); err != nil {
				slog.Warn("tse write failed", "err", err)
			}
		}()
	}
}

func (h *SyncHandler) handleEDRActionsPending(w http.ResponseWriter, r *http.Request) {
	agentID := ctxAgentID(r)
	if agentID == "" {
		writeAPIError(w, r, http.StatusUnauthorized, "agent auth required")
		return
	}
	limit := clampInt(parseLimit(r), 1, 50)
	rows, err := h.manager.db.QueryContext(r.Context(),
		`SELECT id, action_type, target, params, timeout_seconds FROM edr_actions
		 WHERE agent_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT ?`, agentID, limit)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()
	type action struct {
		ID      string         `json:"id"`
		Type    string         `json:"type"`
		Target  string         `json:"target,omitempty"`
		Params  map[string]any `json:"params,omitempty"`
		Timeout int            `json:"timeout_seconds"`
	}
	actions := []*action{}
	for rows.Next() {
		var a action
		var paramsStr string
		if err := rows.Scan(&a.ID, &a.Type, &a.Target, &paramsStr, &a.Timeout); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(paramsStr), &a.Params)
		actions = append(actions, &a)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	if actions == nil {
		actions = []*action{}
	}
	writeData(w, r, http.StatusOK, map[string]any{"actions": actions})
}

func (h *SyncHandler) handleEDRAlertDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		AlertID string `json:"alert_id"`
		Reason  string `json:"reason,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AlertID == "" {
		writeAPIError(w, r, http.StatusBadRequest, "alert_id required")
		return
	}
	if !validResourceID(strings.ReplaceAll(req.AlertID, "/", "")) || len(req.AlertID) > maxResourceIDLen {
		writeAPIError(w, r, http.StatusBadRequest, "invalid alert_id")
		return
	}
	var ruleName, processName string
	_ = h.manager.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(json_extract(data, '$.annotations.yara_rule'), json_extract(data, '$.annotations.correlation'), event_type),
				COALESCE(json_extract(data, '$.process.name'), json_extract(data, '$.file.path'), 'unknown')
		 FROM edr_events WHERE id = ?`, req.AlertID).Scan(&ruleName, &processName)
	if ruleName == "" {
		prefix := shortID(req.AlertID)
		if prefix == "" {
			prefix = "unknown"
		}
		ruleName = "manual_" + prefix
	}
	if processName == "" {
		processName = "unknown"
	}
	orgID := OrgIDFromContext(r.Context())
	result, err := h.manager.db.ExecContext(r.Context(),
		`INSERT INTO edr_fp_counters (rule_name, process_name, dismissals, throttled, org_id, last_seen)
		 VALUES (?, ?, 1, 0, ?, datetime('now'))
		 ON CONFLICT(rule_name, process_name) DO UPDATE SET
		   dismissals = dismissals + 1,
		   throttled = CASE WHEN dismissals + 1 >= 10 THEN 1 ELSE 0 END,
		   last_seen = datetime('now')`,
		ruleName, processName, orgID)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "dismiss failed")
		return
	}
	var dismissals int
	var throttled bool
	_ = h.manager.db.QueryRowContext(r.Context(),
		`SELECT dismissals, throttled FROM edr_fp_counters WHERE rule_name = ? AND process_name = ?`,
		ruleName, processName).Scan(&dismissals, &throttled)
	_ = result
	auditWrite(h.audit, r.Context(), auditActor(r), "alert.dismissed", "alert", req.AlertID,
		"rule="+ruleName+" process="+processName)
	writeData(w, r, http.StatusOK, map[string]any{
		"status": "dismissed", "rule_name": ruleName,
		"process_name": processName, "dismissals": dismissals, "throttled": throttled,
	})
}

func (h *SyncHandler) handleEDRActionResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	agentID := ctxAgentID(r)
	if agentID == "" {
		writeAPIError(w, r, http.StatusUnauthorized, "agent auth required")
		return
	}
	var result struct {
		AgentID    string         `json:"agent_id"` // ignored: ctx is authoritative
		ActionID   string         `json:"action_id"`
		Status     string         `json:"status"`
		Error      string         `json:"error,omitempty"`
		Output     map[string]any `json:"output,omitempty"`
		ExecutedAt string         `json:"executed_at"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if !validResourceID(result.ActionID) {
		writeAPIError(w, r, http.StatusBadRequest, "invalid action_id")
		return
	}
	if result.Status != "completed" && result.Status != "failed" && result.Status != "timeout" {
		writeAPIError(w, r, http.StatusBadRequest, "invalid status")
		return
	}
	outputJSON, _ := json.Marshal(result.Output)
	if len(outputJSON) > 64<<10 {
		outputJSON = []byte(`{"truncated":true}`)
	}
	res, err := h.manager.db.ExecContext(r.Context(),
		`UPDATE edr_actions SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ? AND agent_id = ?`,
		result.Status, string(outputJSON), result.Error, result.ExecutedAt, result.ActionID, agentID)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "update failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Cross-agent result or unknown action: acknowledge but affect nothing.
		h.metrics.incAuthFailure("cross_agent_result")
		writeAPIError(w, r, http.StatusNotFound, "action not found for this agent")
		return
	}
	h.metrics.actionResults.Add(1)
	auditWrite(h.audit, r.Context(), "agent:"+shortID(agentID), "action.result", "action", result.ActionID, "status="+result.Status)
	writeData(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *SyncHandler) handleEDRDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		AgentID  string         `json:"agent_id"`
		ActionID string         `json:"action_id,omitempty"`
		Action   string         `json:"action_type"`
		Target   string         `json:"target,omitempty"`
		Params   map[string]any `json:"params,omitempty"`
		Timeout  int            `json:"timeout_seconds"`
	}
	// Compat: accept both action_type and action keys.
	var raw map[string]any
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	rawBytes, _ := json.Marshal(raw)
	_ = json.Unmarshal(rawBytes, &req)
	if a, _ := raw["action"].(string); a != "" && req.Action == "" {
		req.Action = a
	}
	if a, _ := raw["action_type"].(string); a != "" {
		req.Action = a
	}
	if !validResourceID(req.AgentID) {
		writeAPIError(w, r, http.StatusBadRequest, "agent_id and action_type required")
		return
	}
	if !allowedDispatchActions[req.Action] {
		writeAPIError(w, r, http.StatusBadRequest, "action_type not allowed: "+req.Action)
		return
	}
	if err := validateDispatchParams(req.Action, req.Params); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if req.Target != "" && len(req.Target) > 1024 {
		writeAPIError(w, r, http.StatusBadRequest, "target too long")
		return
	}
	if req.Timeout <= 0 || req.Timeout > 600 {
		req.Timeout = 30
	}
	// Verify the target agent belongs to the caller's org (tenant containment).
	orgID := OrgIDFromContext(r.Context())
	var agentOrg string
	if err := h.manager.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(org_id, '') FROM edr_agents WHERE id = ?`, req.AgentID).Scan(&agentOrg); err != nil {
		writeAPIError(w, r, http.StatusNotFound, "agent not found")
		return
	}
	if orgID != "" && agentOrg != orgID {
		writeAPIError(w, r, http.StatusForbidden, "agent belongs to another organization")
		return
	}
	// Destructive actions stay deny-closed without approval (0.9 binds tokens;
	// until then record pending_approval so nothing executes).
	status := "pending"
	if destructiveActions[req.Action] {
		status = "pending_approval"
	}
	paramsJSON, _ := json.Marshal(req.Params)
	id := req.ActionID
	if id == "" {
		newID, err := uuid.NewV7()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "mint id failed")
			return
		}
		id = newID.String()
	} else if err := uuid.Validate(id); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid action_id (must be UUID)")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	actor := auditActor(r)
	if key := r.Header.Get(idempotencyHeader); key != "" {
		reqHash := hashSecret(string(rawBytes))
		if st, prev, dup := h.manager.checkIdempotency(r.Context(), "dispatch:"+key, actor, reqHash); dup {
			if st == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":"duplicate request: already in progress or completed","code":409}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(prev))
			return
		}
	}
	_, err := h.manager.db.ExecContext(r.Context(),
		`INSERT INTO edr_actions (id, agent_id, action_type, target, params, status, timeout_seconds, org_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.AgentID, req.Action, req.Target, string(paramsJSON), status, req.Timeout, agentOrg, now)
	if err != nil {
		if key := r.Header.Get(idempotencyHeader); key != "" {
			h.manager.finishIdempotency(r.Context(), "dispatch:"+key, actor, 0, "")
		}
		writeAPIError(w, r, http.StatusInternalServerError, "insert failed")
		return
	}
	h.metrics.dispatches.Add(1)
	auditWrite(h.audit, r.Context(), actor, "action.dispatched", "action", id,
		"agent="+shortID(req.AgentID)+" type="+req.Action+" status="+status)
	respBody, _ := json.Marshal(Envelope{Data: map[string]string{"action_id": id, "status": status},
		Code: http.StatusOK, RequestID: RequestIDFromContext(r.Context())})
	if key := r.Header.Get(idempotencyHeader); key != "" {
		h.manager.finishIdempotency(r.Context(), "dispatch:"+key, actor, http.StatusOK, string(respBody))
	}
	slog.Info("action dispatched", "action", shortID(id), "agent", shortID(req.AgentID), "type", req.Action)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBody)
}

// splitHostPort tolerant split (avoids net import churn in edr handlers).
func splitHostPort(addr string) (string, string, error) {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i], addr[i+1:], nil
	}
	return addr, "", nil
}

// edrEventsQuery is the fleet/user events read path. Agents see only their
// own ctx-bound stream; users with PermAgentRead may query one agent at a
// time within their org.
func (h *SyncHandler) handleEDREventsQuery(w http.ResponseWriter, r *http.Request) {
	agentID := ctxAgentID(r)
	if agentID == "" {
		// User-key path: explicit agent_id required, org-scoped.
		if !HasPermission(RoleFromContext(r.Context()), PermAgentRead) {
			writeAPIError(w, r, http.StatusForbidden, "insufficient permissions")
			return
		}
		agentID = r.URL.Query().Get("agent_id")
		if !validResourceID(agentID) {
			writeAPIError(w, r, http.StatusBadRequest, "agent_id required")
			return
		}
		var agentOrg string
		if err := h.manager.db.QueryRowContext(r.Context(),
			`SELECT COALESCE(org_id, '') FROM edr_agents WHERE id = ?`, agentID).Scan(&agentOrg); err != nil {
			writeAPIError(w, r, http.StatusNotFound, "agent not found")
			return
		}
		if orgID := OrgIDFromContext(r.Context()); orgID != "" && agentOrg != orgID {
			writeAPIError(w, r, http.StatusForbidden, "agent belongs to another organization")
			return
		}
	}
	limit := parseLimit(r)
	offset := parseCursor(r)
	eventType := r.URL.Query().Get("type")
	if len(eventType) > 64 {
		eventType = eventType[:64]
	}
	minSev := 0
	if s, err := strconv.Atoi(r.URL.Query().Get("min_severity")); err == nil && s > 0 {
		minSev = clampInt(s, 1, 10)
	}
	q := `SELECT id, event_type, severity, timestamp, data FROM edr_events WHERE agent_id = ?`
	args := []any{agentID}
	if eventType != "" {
		q += ` AND event_type = ?`
		args = append(args, eventType)
	}
	if minSev > 0 {
		q += ` AND severity >= ?`
		args = append(args, minSev)
	}
	q += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := h.manager.db.QueryContext(r.Context(), q, args...)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()
	type evt struct {
		ID        string `json:"id"`
		EventType string `json:"event_type"`
		Severity  int    `json:"severity"`
		Timestamp string `json:"timestamp"`
		Data      string `json:"data,omitempty"`
	}
	events := make([]evt, 0, limit)
	for rows.Next() {
		var e evt
		if err := rows.Scan(&e.ID, &e.EventType, &e.Severity, &e.Timestamp, &e.Data); err != nil {
			continue
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	next := ""
	if len(events) > limit {
		events = events[:limit]
		next = encodeCursor(offset + limit)
	}
	writeData(w, r, http.StatusOK, map[string]any{
		"events": events, "next_cursor": next,
	})
}

// vulnFeedQuery is the shared query behind agent + user vuln reads.
func (h *SyncHandler) vulnFeedQuery(r *http.Request, agentID string) ([]map[string]any, error) {
	minSev := 0
	if s, err := strconv.Atoi(r.URL.Query().Get("min_severity")); err == nil && s > 0 {
		minSev = clampInt(s, 1, 10)
	}
	limit := clampInt(parseLimit(r), 1, 100)
	rows, err := h.manager.db.QueryContext(r.Context(),
		`SELECT id, event_type, severity, data, timestamp FROM edr_events
		 WHERE agent_id = ? AND event_type = 'alert'
		 AND json_extract(data, '$.annotations.source') = 'vuln_scan'
		 AND severity >= ?
		 ORDER BY timestamp DESC LIMIT ?`, agentID, minSev, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vulns := make([]map[string]any, 0)
	for rows.Next() {
		var id, etype, data, ts string
		var sev int
		if err := rows.Scan(&id, &etype, &sev, &data, &ts); err != nil {
			continue
		}
		var full struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal([]byte(data), &full); err != nil {
			continue
		}
		vulns = append(vulns, map[string]any{
			"id": id, "cve_id": full.Annotations["cve_id"], "package": full.Annotations["package"],
			"cvss": full.Annotations["cvss"], "severity": full.Annotations["severity"],
			"fixed_in": full.Annotations["fixed_in"], "timestamp": ts,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return vulns, nil
}

func (h *SyncHandler) handleEDRVulns(w http.ResponseWriter, r *http.Request) {
	agentID := ctxAgentID(r)
	if agentID == "" {
		if !HasPermission(RoleFromContext(r.Context()), PermAgentRead) {
			writeAPIError(w, r, http.StatusForbidden, "insufficient permissions")
			return
		}
		agentID = r.URL.Query().Get("agent_id")
		if !validResourceID(agentID) {
			writeAPIError(w, r, http.StatusBadRequest, "agent_id required")
			return
		}
	}
	vulns, err := h.vulnFeedQuery(r, agentID)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"vulns": vulns})
}

// provisionTokenFromRequest extracts an enrollment token from header or body.
func provisionTokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("X-Provision-Token"); h != "" {
		return strings.TrimSpace(h)
	}
	return ""
}

// sanitizeURLQuery rebuilds a query string with only allowlisted keys (used
// by CLI compat paths; server never reflects raw query strings).
func sanitizeURLQuery(v url.Values, allow ...string) string {
	out := url.Values{}
	for _, k := range allow {
		if s := v.Get(k); s != "" {
			out.Set(k, s)
		}
	}
	return out.Encode()
}

func (h *SyncHandler) handleEDRAgentsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET required")
		return
	}
	onlyActive := r.URL.Query().Get("all") != "true"
	limit := parseLimit(r)
	offset := parseCursor(r)
	query := `SELECT id, hostname, platform, arch, agent_version, status, ip_address, last_heartbeat, cpu_count, cpu_name, memory_mb, created_at
		 FROM edr_agents WHERE 1=1`
	var args []any
	if onlyActive {
		query += ` AND status = 'active'`
	}
	query += orgPredicate(r.Context(), &args)
	query += ` ORDER BY last_heartbeat DESC LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := h.manager.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()
	type agent struct {
		ID            string `json:"id"`
		Hostname      string `json:"hostname"`
		Platform      string `json:"platform"`
		Arch          string `json:"arch"`
		Version       string `json:"version"`
		Status        string `json:"status"`
		IP            string `json:"ip"`
		LastHeartbeat string `json:"last_heartbeat"`
		CPUCount      int    `json:"cpu_count"`
		CPUName       string `json:"cpu_name"`
		MemoryMB      int64  `json:"memory_mb"`
		CreatedAt     string `json:"created_at"`
	}
	agents := []*agent{}
	for rows.Next() {
		var a agent
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Platform, &a.Arch, &a.Version, &a.Status, &a.IP, &a.LastHeartbeat, &a.CPUCount, &a.CPUName, &a.MemoryMB, &a.CreatedAt); err != nil {
			continue
		}
		agents = append(agents, &a)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	next := ""
	if len(agents) > limit {
		agents = agents[:limit]
		next = encodeCursor(offset + limit)
	}
	writeData(w, r, http.StatusOK, map[string]any{"agents": agents, "next_cursor": next})
}

func (h *SyncHandler) handleEDRAgentByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/edr/agents/")
	id = strings.TrimSuffix(id, "/")
	if !validResourceID(id) {
		writeAPIError(w, r, http.StatusBadRequest, "agent_id required")
		return
	}
	if r.Method == http.MethodDelete {
		// Tenant containment first: never revoke across orgs.
		if orgID := OrgIDFromContext(r.Context()); orgID != "" {
			var agentOrg string
			if err := h.manager.db.QueryRowContext(r.Context(),
				`SELECT COALESCE(org_id, '') FROM edr_agents WHERE id = ?`, id).Scan(&agentOrg); err != nil {
				writeAPIError(w, r, http.StatusNotFound, "agent not found")
				return
			}
			if agentOrg != "" && agentOrg != orgID {
				writeAPIError(w, r, http.StatusForbidden, "agent belongs to another organization")
				return
			}
		}
		res, err := h.manager.db.ExecContext(r.Context(),
			`UPDATE edr_agents SET status = 'revoked' WHERE id = ?`, id)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "revoke failed")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeAPIError(w, r, http.StatusNotFound, "agent not found")
			return
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "agent.revoked", "agent", id, "")
		writeData(w, r, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET or DELETE required")
		return
	}
	var a struct {
		ID        string `json:"id"`
		Hostname  string `json:"hostname"`
		Platform  string `json:"platform"`
		Arch      string `json:"arch"`
		Version   string `json:"version"`
		Status    string `json:"status"`
		IP        string `json:"ip"`
		LastSeen  string `json:"last_heartbeat"`
		CPUCount  int    `json:"cpu_count"`
		CPUName   string `json:"cpu_name"`
		MemoryMB  int64  `json:"memory_mb"`
		CreatedAt string `json:"created_at"`
	}
	q := `SELECT id, hostname, platform, arch, agent_version, status, ip_address, last_heartbeat, cpu_count, cpu_name, memory_mb, created_at
		 FROM edr_agents WHERE id = ?`
	args := []any{id}
	q += orgPredicate(r.Context(), &args)
	err := h.manager.db.QueryRowContext(r.Context(), q, args...).Scan(
		&a.ID, &a.Hostname, &a.Platform, &a.Arch, &a.Version, &a.Status, &a.IP, &a.LastSeen, &a.CPUCount, &a.CPUName, &a.MemoryMB, &a.CreatedAt)
	if err != nil {
		writeAPIError(w, r, http.StatusNotFound, "agent not found")
		return
	}
	writeData(w, r, http.StatusOK, a)
}
