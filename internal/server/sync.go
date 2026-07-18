package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

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

type ServeOptions struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	LogDir     string
}

func ServeHTTP(opts ServeOptions, mgr *ServerManager, dashboard DashboardDataProvider) (*http.Server, error) {
	mux := http.NewServeMux()

	sync := NewSyncHandler(mgr).WithLogDir(opts.LogDir)
	sync.RegisterRoutes(mux)

	dashboardHandler := NewDashboardHandler(dashboard)
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
