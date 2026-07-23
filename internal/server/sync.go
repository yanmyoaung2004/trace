package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yanmyoaung2004/trace/internal/investigation"
)

type SyncHandler struct {
	manager  *ServerManager
	logDir   string
}

func NewSyncHandler(mgr *ServerManager) *SyncHandler {
	return &SyncHandler{manager: mgr}
}

func (h *SyncHandler) WithLogDir(dir string) *SyncHandler {
	h.logDir = dir
	return h
}

func (h *SyncHandler) RegisterRoutes(mux *http.ServeMux) {
	protected := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.URL.Query().Get("api_key")
			if apiKey == "" {
				if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
					apiKey = strings.TrimPrefix(auth, "Bearer ")
				}
			}
			if apiKey != "" {
				if userID, role, err := h.manager.Authenticate(r.Context(), apiKey); err == nil && userID != "" {
					ctx := context.WithValue(r.Context(), ctxKeyRole, role)
					r = r.WithContext(ctx)
					handler(w, r)
					return
				}
			}
			writeError(w, http.StatusUnauthorized, "unauthorized — provide api_key query param or Authorization: Bearer <key>")
		}
	}

	readOnly := func(handler http.HandlerFunc) http.HandlerFunc {
		return protected(func(w http.ResponseWriter, r *http.Request) {
			handler(w, r)
		})
	}

	mux.HandleFunc("/api/v1/register", protected(h.handleRegister))
	mux.HandleFunc("/api/v1/heartbeat", protected(h.handleHeartbeat))
	mux.HandleFunc("/api/v1/push", protected(h.handlePush))
	mux.HandleFunc("/api/v1/nodes", readOnly(h.handleNodes))
	mux.HandleFunc("/api/v1/investigations/", readOnly(h.handleInvestigationByID))
	mux.HandleFunc("/api/v1/investigations", readOnly(h.handleInvestigations))
	mux.HandleFunc("/api/v1/correlations", readOnly(h.handleCorrelations))
	mux.HandleFunc("/api/v1/timeline/", readOnly(h.handleTimeline))

	mux.HandleFunc("/api/v1/edr/register", h.handleEDRRegister)
	mux.HandleFunc("/api/v1/edr/heartbeat", h.handleEDRHeartbeat)
	mux.HandleFunc("/api/v1/edr/events", h.handleEDREvents)
	mux.HandleFunc("/api/v1/edr/actions/pending", h.handleEDRActionsPending)
	mux.HandleFunc("/api/v1/edr/actions/result", h.handleEDRActionResult)
	mux.HandleFunc("/api/v1/edr/actions/dispatch", protected(h.handleEDRDispatch))
	mux.HandleFunc("/api/v1/edr/alerts/dismiss", protected(h.handleEDRAlertDismiss))
	mux.HandleFunc("/api/v1/edr/agents", readOnly(h.handleEDRAgentsList))
	mux.HandleFunc("/api/v1/edr/agents/", readOnly(h.handleEDRAgentByID))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

type contextKey string

const ctxKeyRole contextKey = "role"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *SyncHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
		Version  string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required")
		return
	}
	node, err := h.manager.RegisterNode(r.Context(), req.Hostname, req.Version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("[sync] node registered: %s (%s)", node.ID[:12], node.Hostname)
	writeJSON(w, http.StatusOK, node)
}

func (h *SyncHandler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := h.manager.Heartbeat(r.Context(), req.NodeID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "ok",
		"server_time": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *SyncHandler) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		NodeID       string              `json:"node_id"`
		Investigation *InvestigationPush `json:"investigation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.NodeID == "" || req.Investigation == nil {
		writeError(w, http.StatusBadRequest, "node_id and investigation are required")
		return
	}
	inv := req.Investigation
	if err := h.manager.PushInvestigation(r.Context(), req.NodeID, inv.ID, inv.Status,
		inv.Intent, inv.Playbook, inv.Summary, inv.Confidence, inv.Indicators, inv.Report); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"accepted": true})
}

type InvestigationPush struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	Intent      string    `json:"intent"`
	Playbook    string    `json:"playbook,omitempty"`
	Confidence  *float64  `json:"confidence,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Indicators  []string  `json:"indicators,omitempty"`
	Report      string    `json:"report,omitempty"`
}

func (h *SyncHandler) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.manager.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []NodeInfo{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (h *SyncHandler) handleInvestigations(w http.ResponseWriter, r *http.Request) {
	limit := 100
	nodeID := r.URL.Query().Get("node_id")
	statusFilter := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")

	invs, err := h.manager.ListInvestigations(r.Context(), limit, nodeID, statusFilter, search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if invs == nil {
		invs = []ServerInvestigation{}
	}
	writeJSON(w, http.StatusOK, invs)
}

func (h *SyncHandler) handleInvestigationByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/investigations/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}
	inv, err := h.manager.GetInvestigation(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "investigation not found")
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

func (h *SyncHandler) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	corrs, err := h.manager.GetCorrelations(r.Context(), 1)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if corrs == nil {
		corrs = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, corrs)
}

func (h *SyncHandler) handleTimeline(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/timeline/")
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "investigation ID is required")
		return
	}

	if h.logDir == "" {
		writeError(w, http.StatusNotFound, "log directory not configured")
		return
	}

	entries, err := investigation.ReadInvestigationLog(h.logDir, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []investigation.LogEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// ── EDR Agent Handlers ──

func (h *SyncHandler) handleEDRRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Hostname      string `json:"hostname"`
		Platform      string `json:"platform"`
		Arch          string `json:"arch"`
		Version       string `json:"version"`
		KernelVersion string `json:"kernel_version,omitempty"`
		CPUCount      int    `json:"cpu_count"`
		CPUName       string `json:"cpu_name"`
		MemoryMB      int64  `json:"memory_mb"`
		AgentVersion  string `json:"agent_version"`
		Monitors      string `json:"monitors"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname required")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}

	_, err := h.manager.db.ExecContext(r.Context(),
		`INSERT INTO edr_agents (id, hostname, platform, arch, version, agent_version, status, ip_address, cpu_count, cpu_name, memory_mb, kernel_version, monitors, last_heartbeat, last_ip, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.Hostname, req.Platform, req.Arch, req.Version, req.AgentVersion, ip, req.CPUCount, req.CPUName, req.MemoryMB, req.KernelVersion, req.Monitors, now, ip, now, now)
	if err != nil {
		log.Printf("[edr] register error: %v", err)
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}

	log.Printf("[edr] agent registered: %s (%s/%s)", req.Hostname, req.Platform, req.Arch)
	writeJSON(w, http.StatusOK, map[string]string{"agent_id": id, "status": "registered"})
}

func (h *SyncHandler) handleEDRHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var hb struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Status   string `json:"status"`
		Version  string `json:"version"`
		Uptime   int64  `json:"uptime"`
		Stats    struct {
			EventsCollected int64   `json:"events_collected"`
			EventsSent      int64   `json:"events_sent"`
			ActionsExecuted int64   `json:"actions_executed"`
			ActionsFailed   int64   `json:"actions_failed"`
			CPUPercent      float64 `json:"cpu_percent"`
			MemoryMB        int64   `json:"memory_mb"`
		} `json:"stats"`
	}
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}

	_, err := h.manager.db.ExecContext(r.Context(),
		`UPDATE edr_agents SET status = ?, last_heartbeat = ?, last_ip = ?, updated_at = ? WHERE id = ?`,
		hb.Status, now, ip, now, hb.AgentID)
	if err != nil {
		log.Printf("[edr] heartbeat error: %v", err)
	}
}

func (h *SyncHandler) handleEDREvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.handleEDREventsQuery(w, r)
		return
	}
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "POST or GET")
		return
	}
	var body struct {
		AgentID string `json:"agent_id"`
		Events  []json.RawMessage `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	tx, err := h.manager.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(r.Context(),
		`INSERT INTO edr_events (id, agent_id, event_type, severity, data, timestamp, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "prepare error")
		return
	}
	defer stmt.Close()

	stored := 0
	for _, raw := range body.Events {
		var evt struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Severity  int    `json:"severity"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(raw, &evt); err != nil || evt.ID == "" {
			continue
		}
		if _, err := stmt.ExecContext(r.Context(), evt.ID, body.AgentID, evt.Type, evt.Severity, string(raw), evt.Timestamp); err != nil {
			log.Printf("[edr] event insert error: %v", err)
			continue
		}
		stored++
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "commit error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"stored": stored, "received": len(body.Events)})
}

func (h *SyncHandler) handleEDRActionsPending(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}

	rows, err := h.manager.db.QueryContext(r.Context(),
		`SELECT id, action_type, target, params, timeout_seconds FROM edr_actions
		 WHERE agent_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 10`, agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()

	type action struct {
		ID      string           `json:"id"`
		Type    string           `json:"type"`
		Target  string           `json:"target,omitempty"`
		Params  map[string]any   `json:"params,omitempty"`
		Timeout int              `json:"timeout_seconds"`
	}

	actions := []*action{}
	for rows.Next() {
		var a action
		var paramsStr string
		if err := rows.Scan(&a.ID, &a.Type, &a.Target, &paramsStr, &a.Timeout); err != nil {
			continue
		}
		json.Unmarshal([]byte(paramsStr), &a.Params)
		actions = append(actions, &a)
	}

	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (h *SyncHandler) handleEDRAlertDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		AlertID string `json:"alert_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AlertID == "" {
		writeError(w, http.StatusBadRequest, "alert_id required")
		return
	}

	// Look up the alert to find rule_name and process_name
	var ruleName, processName string
	h.manager.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(json_extract(data, '$.yara_rule'), json_extract(data, '$.correlation'), event_type),
				COALESCE(json_extract(data, '$.process_name'), 'unknown')
		 FROM edr_events WHERE id = ?`, req.AlertID).Scan(&ruleName, &processName)
	if ruleName == "" {
		ruleName = "manual_" + req.AlertID[:8]
	}
	if processName == "" {
		processName = "unknown"
	}

	// Upsert the counter
	result, err := h.manager.db.ExecContext(r.Context(),
		`INSERT INTO edr_fp_counters (rule_name, process_name, dismissals, throttled, last_seen)
		 VALUES (?, ?, 1, 0, datetime('now'))
		 ON CONFLICT(rule_name, process_name) DO UPDATE SET
		   dismissals = dismissals + 1,
		   throttled = CASE WHEN dismissals + 1 >= 10 THEN 1 ELSE 0 END,
		   last_seen = datetime('now')`,
		ruleName, processName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dismiss failed")
		return
	}

	var dismissals int
	var throttled bool
	row := h.manager.db.QueryRowContext(r.Context(),
		`SELECT dismissals, throttled FROM edr_fp_counters WHERE rule_name = ? AND process_name = ?`,
		ruleName, processName)
	row.Scan(&dismissals, &throttled)

	_ = result
	log.Printf("[edr] alert %s dismissed: rule=%s process=%s (count=%d, throttled=%v)",
		req.AlertID, ruleName, processName, dismissals, throttled)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "dismissed",
		"rule_name":    ruleName,
		"process_name": processName,
		"dismissals":   dismissals,
		"throttled":    throttled,
	})
}

func (h *SyncHandler) handleEDRActionResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var result struct {
		AgentID    string         `json:"agent_id"`
		ActionID   string         `json:"action_id"`
		Status     string         `json:"status"`
		Error      string         `json:"error,omitempty"`
		Output     map[string]any `json:"output,omitempty"`
		ExecutedAt string         `json:"executed_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	outputJSON, _ := json.Marshal(result.Output)
	_, err := h.manager.db.ExecContext(r.Context(),
		`UPDATE edr_actions SET status = ?, result = ?, error = ?, completed_at = ? WHERE id = ?`,
		result.Status, string(outputJSON), result.Error, result.ExecutedAt, result.ActionID)
	if err != nil {
		log.Printf("[edr] action result error: %v", err)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *SyncHandler) handleEDRAgentsList(w http.ResponseWriter, r *http.Request) {
	onlyActive := r.URL.Query().Get("all") != "true"
	query := `SELECT id, hostname, platform, arch, agent_version, status, ip_address, last_heartbeat, cpu_count, cpu_name, memory_mb, created_at
		 FROM edr_agents`
	if onlyActive {
		query += ` WHERE status = 'active'`
	}
	query += ` ORDER BY last_heartbeat DESC`
	rows, err := h.manager.db.QueryContext(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query error")
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

	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

func (h *SyncHandler) handleEDRAgentByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/edr/agents/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}

	if r.Method == "DELETE" {
		_, err := h.manager.db.ExecContext(r.Context(),
			`UPDATE edr_agents SET status = 'revoked' WHERE id = ?`, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "revoke failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		return
	}

	// GET agent detail
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
	err := h.manager.db.QueryRowContext(r.Context(),
		`SELECT id, hostname, platform, arch, agent_version, status, ip_address, last_heartbeat, cpu_count, cpu_name, memory_mb, created_at
		 FROM edr_agents WHERE id = ?`, id).Scan(
		&a.ID, &a.Hostname, &a.Platform, &a.Arch, &a.Version, &a.Status, &a.IP, &a.LastSeen, &a.CPUCount, &a.CPUName, &a.MemoryMB, &a.CreatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *SyncHandler) handleEDREventsQuery(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id required")
		return
	}

	limit := 50
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	eventType := r.URL.Query().Get("type")
	minSev := 0
	if s, err := strconv.Atoi(r.URL.Query().Get("min_severity")); err == nil && s > 0 {
		minSev = s
	}

	var rows *sql.Rows
	var err error
	if eventType != "" && minSev > 0 {
		rows, err = h.manager.db.QueryContext(r.Context(),
			`SELECT event_type, severity, timestamp, data FROM edr_events
			 WHERE agent_id = ? AND event_type LIKE ? AND severity >= ? ORDER BY timestamp DESC LIMIT ?`,
			agentID, eventType+"%", minSev, limit)
	} else if eventType != "" {
		rows, err = h.manager.db.QueryContext(r.Context(),
			`SELECT event_type, severity, timestamp, data FROM edr_events
			 WHERE agent_id = ? AND event_type LIKE ? ORDER BY timestamp DESC LIMIT ?`,
			agentID, eventType+"%", limit)
	} else if minSev > 0 {
		rows, err = h.manager.db.QueryContext(r.Context(),
			`SELECT event_type, severity, timestamp, data FROM edr_events
			 WHERE agent_id = ? AND severity >= ? ORDER BY timestamp DESC LIMIT ?`,
			agentID, minSev, limit)
	} else {
		rows, err = h.manager.db.QueryContext(r.Context(),
			`SELECT event_type, severity, timestamp, data FROM edr_events
			 WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?`, agentID, limit)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()

	type evt struct {
		EventType string `json:"event_type"`
		Severity  int    `json:"severity"`
		Timestamp string `json:"timestamp"`
		Data      string `json:"data,omitempty"`
	}

	events := make([]evt, 0, limit)
	for rows.Next() {
		var e evt
		rows.Scan(&e.EventType, &e.Severity, &e.Timestamp, &e.Data)
		events = append(events, e)
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (h *SyncHandler) handleEDRDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req struct {
		AgentID    string         `json:"agent_id"`
		ActionType string         `json:"action_type"`
		Target     string         `json:"target,omitempty"`
		Params     map[string]any `json:"params,omitempty"`
		Timeout    int            `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.AgentID == "" || req.ActionType == "" {
		writeError(w, http.StatusBadRequest, "agent_id and action_type required")
		return
	}
	if req.Timeout <= 0 {
		req.Timeout = 30
	}

	paramsJSON, _ := json.Marshal(req.Params)
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := h.manager.db.ExecContext(r.Context(),
		`INSERT INTO edr_actions (id, agent_id, action_type, target, params, status, timeout_seconds, created_at)
		 VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`,
		id, req.AgentID, req.ActionType, req.Target, string(paramsJSON), req.Timeout, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "insert failed")
		return
	}

	log.Printf("[edr] action dispatched: %s → %s (%s)", id, req.AgentID, req.ActionType)
	writeJSON(w, http.StatusOK, map[string]string{"action_id": id, "status": "dispatched"})
}

type ServeOptions struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	LogDir     string
	DB         *sql.DB
}

func ServeHTTP(opts ServeOptions, mgr *ServerManager, dashboard DashboardDataProvider) (*http.Server, error) {
	mux := http.NewServeMux()

	sync := NewSyncHandler(mgr).WithLogDir(opts.LogDir)
	sync.RegisterRoutes(mux)

	dashboardHandler := NewDashboardHandler(dashboard)
	if opts.DB != nil {
		dashboardHandler.WithDB(opts.DB)
	}
	dashboardHandler.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		if opts.CertFile != "" && opts.KeyFile != "" {
			log.Printf("[server] HTTPS API + dashboard on %s (TLS)", opts.ListenAddr)
			if err := srv.ListenAndServeTLS(opts.CertFile, opts.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("[server] HTTPS error: %v", err)
			}
		} else {
			log.Printf("[server] HTTP API + dashboard on %s", opts.ListenAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[server] HTTP error: %v", err)
			}
		}
	}()

	return srv, nil
}

func init() {
	_ = context.Background()
}
