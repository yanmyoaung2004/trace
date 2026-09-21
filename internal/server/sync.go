package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"log/slog"

	"github.com/yanmyoaung2004/trace/internal/cases"
	"github.com/yanmyoaung2004/trace/internal/investigation"
	"github.com/yanmyoaung2004/trace/internal/storage"
)

type SyncHandler struct {
	manager     *ServerManager
	logDir      string
	updateDir   string
	configStore *remoteConfigStore
	tseWriter   EventWriter
	auth        *Auth
	metrics     *serverMetrics
	audit       AuditSink
	auditHTTP   http.HandlerFunc
	cases       CasesLister
}

// CasesLister is the seam for scoped paginated case reads, implemented by
// DetectReliabilityFixer's cases.Manager.ListPage (cursor=base64 created_at|id).
// Nil keeps the route returning 501 until injected.
type CasesLister interface {
	ListPage(ctx context.Context, orgID, status, severity string, limit int, cursor string) ([]*cases.Case, string, error)
}

func (h *SyncHandler) WithLogDir(dir string) *SyncHandler {
	h.logDir = dir
	return h
}

func (h *SyncHandler) WithUpdateDir(dir string) *SyncHandler {
	h.updateDir = dir
	return h
}

func (h *SyncHandler) WithConfigStore(s *remoteConfigStore) *SyncHandler {
	h.configStore = s
	return h
}

func (h *SyncHandler) WithTSEWriter(w EventWriter) *SyncHandler {
	h.tseWriter = w
	return h
}

// WithMetrics overrides the default server metrics (ServeHTTP injects shared).
func (h *SyncHandler) WithMetrics(sm *serverMetrics) *SyncHandler {
	if sm != nil {
		h.metrics = sm
		h.auth = newAuth(h.manager, sm).WithAuditSink(h.audit)
	}
	return h
}

// WithAuditLog attaches the audit backend (ConfigAuditFixer adapter).
func (h *SyncHandler) WithAuditLog(s AuditSink) *SyncHandler {
	h.audit = s
	if h.auth != nil {
		h.auth.WithAuditSink(s)
	}
	return h
}

// WithAuditHandler mounts GET /api/v1/audit (ConfigAuditFixer handler).
func (h *SyncHandler) WithAuditHandler(fn http.HandlerFunc) *SyncHandler {
	h.auditHTTP = fn
	return h
}

// WithCasesLister injects the scoped case lister (DetectReliabilityFixer).
func (h *SyncHandler) WithCasesLister(l CasesLister) *SyncHandler {
	h.cases = l
	return h
}

func (h *SyncHandler) RegisterRoutes(mux *http.ServeMux) {
	auth := h.auth
	if auth == nil {
		auth = newAuth(h.manager, h.metrics)
		h.auth = auth
	}
	auditGate := func(next http.HandlerFunc) http.HandlerFunc {
		if h.auditHTTP == nil {
			return func(w http.ResponseWriter, r *http.Request) {
				writeAPIError(w, r, http.StatusNotImplemented, "audit API not configured")
			}
		}
		return auth.RequirePerm(PermAuditRead, h.auditHTTP)
	}

	mux.HandleFunc("/api/v1/register", auth.UserAuth(h.handleRegister))
	mux.HandleFunc("/api/v1/heartbeat", auth.UserAuth(h.handleHeartbeat))
	mux.HandleFunc("/api/v1/push", auth.RequirePerm(PermInvestWrite, h.handlePush))
	mux.HandleFunc("/api/v1/nodes", auth.RequirePerm(PermCaseRead, h.handleNodes))
	mux.HandleFunc("/api/v1/investigations/", auth.RequirePerm(PermInvestRead, h.handleInvestigationByID))
	mux.HandleFunc("/api/v1/investigations", auth.RequirePerm(PermInvestRead, h.handleInvestigations))
	mux.HandleFunc("/api/v1/correlations", auth.RequirePerm(PermInvestRead, h.handleCorrelations))
	mux.HandleFunc("/api/v1/timeline/", auth.RequirePerm(PermInvestRead, h.handleTimeline))
	mux.HandleFunc("/api/v1/cases", auth.RequirePerm(PermCaseRead, h.handleCases))

	// EDR trust boundary: register/download/feed are authed (provision-token
	// enroll, agent-or-user download, agent-self-or-perm vuln reads).
	mux.HandleFunc("/api/v1/edr/register", h.handleEDRRegister)
	mux.HandleFunc("/api/v1/edr/heartbeat", auth.AgentAuth(h.handleEDRHeartbeat))
	mux.HandleFunc("/api/v1/edr/events", auth.FleetOrUser(PermAgentRead, h.handleEDREvents))
	mux.HandleFunc("/api/v1/edr/actions/pending", auth.AgentAuth(h.handleEDRActionsPending))
	mux.HandleFunc("/api/v1/edr/actions/result", auth.AgentAuth(h.handleEDRActionResult))
	mux.HandleFunc("/api/v1/edr/actions/dispatch", auth.RequirePerm(PermAgentWrite, h.handleEDRDispatch))
	mux.HandleFunc("/api/v1/edr/alerts/dismiss", auth.RequirePerm(PermAgentWrite, h.handleEDRAlertDismiss))
	mux.HandleFunc("/api/v1/edr/agents", auth.RequirePerm(PermAgentRead, h.handleEDRAgentsList))
	mux.HandleFunc("/api/v1/edr/agents/", h.handleEDRAgentByIDGate(auth))
	mux.HandleFunc("/api/v1/edr/vulns", auth.FleetOrUser(PermAgentRead, h.handleEDRVulns))
	mux.HandleFunc("/api/v1/edr/update/check", auth.AgentAuth(h.handleEDRUpdateCheck))
	mux.HandleFunc("/api/v1/edr/update/download", auth.FleetOrUser("", h.handleEDRUpdateDownload))
	mux.HandleFunc("/api/v1/edr/config", auth.FleetOrUser(PermAdmin, h.handleEDRConfig))
	mux.HandleFunc("/api/v1/edr/vuln/feed", auth.FleetOrUser(PermAgentRead, h.handleEDRVulnFeed))
	mux.HandleFunc("/api/v1/compliance/snapshot", auth.RequirePerm(PermCompliance, h.handleComplianceSnapshot))
	mux.HandleFunc("/api/v1/admin/orgs", auth.RequirePerm(PermAdmin, h.handleOrgs))
	mux.HandleFunc("/api/v1/admin/users", auth.RequirePerm(PermAdmin, h.handleAdminUsers))
	mux.HandleFunc("/api/v1/admin/users/", auth.RequirePerm(PermAdmin, h.handleAdminUserByEmail))
	mux.HandleFunc("/api/v1/admin/provision-tokens", auth.RequirePerm(PermAdmin, h.handleProvisionTokens))
	mux.HandleFunc("/api/v1/audit", auditGate(nil))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeData(w, r, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// handleEDRAgentByIDGate routes GET (read) vs DELETE (revoke) with per-route perms.
func (h *SyncHandler) handleEDRAgentByIDGate(auth *Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			auth.RequirePerm(PermAgentRevoke, h.handleEDRAgentByID)(w, r)
			return
		}
		auth.RequirePerm(PermAgentRead, h.handleEDRAgentByID)(w, r)
	}
}

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
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Hostname string `json:"hostname"`
		Version  string `json:"version"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Hostname) == "" || len(req.Hostname) > 256 {
		writeAPIError(w, r, http.StatusBadRequest, "hostname is required")
		return
	}
	node, err := h.manager.RegisterNode(r.Context(), strings.TrimSpace(req.Hostname), req.Version)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("node registered", "node", shortID(node.ID), "host", node.Hostname)
	writeData(w, r, http.StatusOK, node)
}

func (h *SyncHandler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if !validResourceID(req.NodeID) {
		writeAPIError(w, r, http.StatusBadRequest, "node_id required")
		return
	}
	if err := h.manager.Heartbeat(r.Context(), req.NodeID); err != nil {
		writeAPIError(w, r, http.StatusNotFound, err.Error())
		return
	}
	writeData(w, r, http.StatusOK, map[string]string{
		"status":      "ok",
		"server_time": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *SyncHandler) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		NodeID        string             `json:"node_id"`
		Investigation *InvestigationPush `json:"investigation"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if !validResourceID(req.NodeID) || req.Investigation == nil {
		writeAPIError(w, r, http.StatusBadRequest, "node_id and investigation are required")
		return
	}
	inv := req.Investigation
	if len(inv.Intent) > 4096 {
		writeAPIError(w, r, http.StatusBadRequest, "intent too long")
		return
	}
	if err := h.manager.PushInvestigation(r.Context(), req.NodeID, inv.ID, inv.Status,
		inv.Intent, inv.Playbook, inv.Summary, inv.Confidence, inv.Indicators, inv.Report); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	auditWrite(h.audit, r.Context(), auditActor(r), "investigation.pushed", "investigation", inv.ID, "")
	writeData(w, r, http.StatusOK, map[string]bool{"accepted": true})
}

type InvestigationPush struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`
	Intent     string   `json:"intent"`
	Playbook   string   `json:"playbook,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	Indicators []string `json:"indicators,omitempty"`
	Report     string   `json:"report,omitempty"`
}

func (h *SyncHandler) handleNodes(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
	offset := parseCursor(r)
	nodes, next, err := h.manager.ListNodes(r.Context(), limit, offset)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []NodeInfo{}
	}
	nextCursor := ""
	if next > 0 {
		nextCursor = encodeCursor(next)
	}
	writeData(w, r, http.StatusOK, pageResponse(nodes, nextCursor))
}

func (h *SyncHandler) handleInvestigations(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
	offset := parseCursor(r)
	nodeID := r.URL.Query().Get("node_id")
	if nodeID != "" && !validResourceID(nodeID) {
		writeAPIError(w, r, http.StatusBadRequest, "invalid node_id")
		return
	}
	statusFilter := r.URL.Query().Get("status")
	if len(statusFilter) > 32 {
		statusFilter = statusFilter[:32]
	}
	search := r.URL.Query().Get("search")

	invs, next, err := h.manager.ListInvestigations(r.Context(), limit, offset, nodeID, statusFilter, search)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if invs == nil {
		invs = []ServerInvestigation{}
	}
	nextCursor := ""
	if next > 0 {
		nextCursor = encodeCursor(next)
	}
	writeData(w, r, http.StatusOK, pageResponse(invs, nextCursor))
}

func (h *SyncHandler) handleInvestigationByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/investigations/")
	id = strings.TrimSuffix(id, "/")
	if !validResourceID(id) {
		writeAPIError(w, r, http.StatusBadRequest, "id is required")
		return
	}
	inv, err := h.manager.GetInvestigation(r.Context(), id)
	if err != nil {
		writeAPIError(w, r, http.StatusNotFound, "investigation not found")
		return
	}
	writeData(w, r, http.StatusOK, inv)
}

func (h *SyncHandler) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r)
	offset := parseCursor(r)
	corrs, next, err := h.manager.GetCorrelations(r.Context(), 1, limit, offset)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if corrs == nil {
		corrs = []map[string]any{}
	}
	nextCursor := ""
	if next > 0 {
		nextCursor = encodeCursor(next)
	}
	writeData(w, r, http.StatusOK, pageResponse(corrs, nextCursor))
}

func (h *SyncHandler) handleTimeline(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/timeline/")
	id = strings.TrimSuffix(id, "/")
	if !validResourceID(id) || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		writeAPIError(w, r, http.StatusBadRequest, "invalid investigation ID")
		return
	}
	if h.logDir == "" {
		writeAPIError(w, r, http.StatusNotFound, "log directory not configured")
		return
	}
	base, err := filepath.Abs(h.logDir)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "log directory error")
		return
	}
	target := filepath.Join(base, id+".jsonl")
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		writeAPIError(w, r, http.StatusBadRequest, "invalid investigation ID")
		return
	}
	entries, err := investigation.ReadInvestigationLog(base, id)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []investigation.LogEntry{}
	}
	writeData(w, r, http.StatusOK, entries)
}

// handleCases serves scoped paginated case reads via the injected CasesLister
// seam (DetectReliabilityFixer owns the manager implementation).
func (h *SyncHandler) handleCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if h.cases == nil {
		writeAPIError(w, r, http.StatusNotImplemented, "cases API not configured")
		return
	}
	limit := parseLimit(r)
	cursor := r.URL.Query().Get("cursor")
	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")
	if len(status) > 32 {
		status = status[:32]
	}
	if len(severity) > 32 {
		severity = severity[:32]
	}
	items, next, err := h.cases.ListPage(r.Context(), OrgIDFromContext(r.Context()), status, severity, limit, cursor)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}
