package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Shared HTTP hardening kit for the central server (FIX_PLAN 0.2 + 0.3 + 1.5).
//
// Contents:
//   - request-ID middleware (ctxKeyRequestID, X-Request-ID header)
//   - standard JSON envelope {data,error,code,request_id}
//   - cursor pagination (?limit&cursor, max enforced, opaque base64 offsets)
//   - idempotency helper contract (Idempotency-Key header; storage in pb.go)
//   - in-memory auth rate-limit / lockout guard (brute-force protection)
//   - HTTP/auth/agent Prometheus-style counters (server-owned; TSE counters
//     stay in internal/storage/metrics, owned by StorageFixer)
//   - AuditSink seam (ConfigAuditFixer injects the real audit.Logger adapter;
//     nil = no-op so the server never hard-depends on audit wiring)
//   - small validation helpers (shortID, validResourceID, clampInt)

const (
	defaultListLimit = 50
	maxListLimit     = 200

	// maxEventsPerPost bounds EDR ingest bodies (413 beyond).
	maxEventsPerPost = 1000
	// maxParamsBytes bounds dispatch params JSON per action.
	maxParamsBytes = 8 << 10
	// maxSearchLen caps free-text search inputs.
	maxSearchLen = 64
	// maxResourceIDLen caps IDs accepted from clients.
	maxResourceIDLen = 128

	requestIDHeader   = "X-Request-ID"
	idempotencyHeader = "Idempotency-Key"
)

// ctxKeyRequestID carries the per-request ID for log correlation.
const ctxKeyRequestID ctxKey = "request_id"

// RequestIDFromContext returns the request ID, or "" if unset.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}

// newRequestID mints a short random request ID (16 hex chars).
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// RequestIDMiddleware assigns a request ID to every request, stores it in the
// context, and echoes it back via the X-Request-ID response header.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Envelope is the standard v1 API response shape.
type Envelope struct {
	Data      any    `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
	Code      int    `json:"code"`
	RequestID string `json:"request_id,omitempty"`
}

// writeData encodes v as a success envelope.
func writeData(w http.ResponseWriter, r *http.Request, status int, v any) {
	env := Envelope{Data: v, Code: status}
	if r != nil {
		env.RequestID = RequestIDFromContext(r.Context())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

// writeAPIError encodes a failure envelope.
func writeAPIError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	var rid string
	if r != nil {
		rid = RequestIDFromContext(r.Context())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Error: msg, Code: status, RequestID: rid})
}

// unwrapEnvelope extracts the inner data payload from a server response.
// It tolerates pre-envelope (bare) payloads for CLI backward compatibility.
func unwrapEnvelope(raw []byte) ([]byte, error) {
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
		Code  int             `json:"code"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if len(env.Data) == 0 && env.Error == "" && env.Code == 0 {
		return raw, nil // not an envelope
	}
	if env.Error != "" {
		return nil, fmt.Errorf("server: %s", env.Error)
	}
	if len(env.Data) == 0 {
		return []byte("null"), nil
	}
	return env.Data, nil
}

// ── Pagination ──

// parseLimit clamps ?limit to [1,maxListLimit], defaulting to defaultListLimit.
func parseLimit(r *http.Request) int {
	limit := defaultListLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}
	return limit
}

// parseCursor decodes an opaque ?cursor (base64 offset) to a row offset.
func parseCursor(r *http.Request) int {
	c := r.URL.Query().Get("cursor")
	if c == "" {
		return 0
	}
	raw, err := base64.URLEncoding.DecodeString(c)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// encodeCursor renders a row offset as an opaque cursor. Empty = end of list.
func encodeCursor(offset int) string {
	return base64.URLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

// pageResponse wraps a list payload with pagination metadata.
func pageResponse(items any, nextCursor string) map[string]any {
	if items == nil {
		items = []any{}
	}
	return map[string]any{"items": items, "next_cursor": nextCursor}
}

// ── Validation helpers ──

// shortID safely truncates an ID for log display (never panics on short IDs).
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// validResourceID reports whether s is a safe client-supplied identifier
// (bounded length, alphanumeric plus - _ . :).
func validResourceID(s string) bool {
	if s == "" || len(s) > maxResourceIDLen {
		return false
	}
	for i := range s {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == ':' {
			continue
		}
		return false
	}
	return true
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// hash presented key material (user keys, provision tokens) with SHA-256.
func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ── Auth rate-limit / lockout guard ──

// authGuard is an in-memory brute-force guard: N failures from one IP or
// against one key hash inside window triggers a temporary lockout (429).
type authGuard struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	locked   map[string]time.Time
	maxFails int
	window   time.Duration
	lockout  time.Duration
}

func newAuthGuard(maxFails int, window, lockout time.Duration) *authGuard {
	return &authGuard{
		failures: map[string][]time.Time{},
		locked:   map[string]time.Time{},
		maxFails: maxFails,
		window:   window,
		lockout:  lockout,
	}
}

func (g *authGuard) blocked(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if until, ok := g.locked[key]; ok {
		if time.Now().Before(until) {
			return true
		}
		delete(g.locked, key)
	}
	return false
}

func (g *authGuard) fail(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-g.window)
	kept := g.failures[key][:0]
	for _, t := range g.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	g.failures[key] = kept
	if len(kept) >= g.maxFails {
		g.locked[key] = now.Add(g.lockout)
		delete(g.failures, key)
	}
}

func (g *authGuard) reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, key)
	delete(g.locked, key)
}

// ── Server-side operational counters ──

// serverMetrics holds HTTP/auth/agent counters owned by internal/server.
// Rendered into /metrics alongside (not instead of) TSE metrics.
type serverMetrics struct {
	mu            sync.Mutex
	requests      map[string]*atomic.Int64 // route|code -> count
	authFailures  map[string]*atomic.Int64 // reason -> count
	registrations atomic.Int64
	heartbeats    atomic.Int64
	dispatches    atomic.Int64
	actionResults atomic.Int64
}

func newServerMetrics() *serverMetrics {
	return &serverMetrics{
		requests:     map[string]*atomic.Int64{},
		authFailures: map[string]*atomic.Int64{},
	}
}

func (m *serverMetrics) incRequest(route string, code int) {
	key := route + "|" + strconv.Itoa(code)
	m.mu.Lock()
	c, ok := m.requests[key]
	if !ok {
		c = &atomic.Int64{}
		m.requests[key] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

func (m *serverMetrics) incAuthFailure(reason string) {
	m.mu.Lock()
	c, ok := m.authFailures[reason]
	if !ok {
		c = &atomic.Int64{}
		m.authFailures[reason] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// prometheusText renders server counters in Prometheus exposition format.
func (m *serverMetrics) prometheusText() string {
	var b strings.Builder
	b.WriteString("# HELP trace_http_requests_total HTTP requests by route and code\n")
	b.WriteString("# TYPE trace_http_requests_total counter\n")
	m.mu.Lock()
	for key, c := range m.requests {
		route, code, _ := strings.Cut(key, "|")
		fmt.Fprintf(&b, "trace_http_requests_total{route=%q,code=%q} %d\n", route, code, c.Load())
	}
	b.WriteString("# HELP trace_auth_failures_total Authentication failures by reason\n")
	b.WriteString("# TYPE trace_auth_failures_total counter\n")
	for reason, c := range m.authFailures {
		fmt.Fprintf(&b, "trace_auth_failures_total{reason=%q} %d\n", reason, c.Load())
	}
	m.mu.Unlock()
	fmt.Fprintf(&b, "# HELP trace_edr_registrations_total EDR agent registrations\n# TYPE trace_edr_registrations_total counter\ntrace_edr_registrations_total %d\n", m.registrations.Load())
	fmt.Fprintf(&b, "# HELP trace_edr_heartbeats_total EDR agent heartbeats\n# TYPE trace_edr_heartbeats_total counter\ntrace_edr_heartbeats_total %d\n", m.heartbeats.Load())
	fmt.Fprintf(&b, "# HELP trace_edr_dispatches_total EDR actions dispatched\n# TYPE trace_edr_dispatches_total counter\ntrace_edr_dispatches_total %d\n", m.dispatches.Load())
	fmt.Fprintf(&b, "# HELP trace_edr_action_results_total EDR action results received\n# TYPE trace_edr_action_results_total counter\ntrace_edr_action_results_total %d\n", m.actionResults.Load())
	return b.String()
}

// ── Audit seam ──

// AuditSink receives best-effort audit events for security-relevant mutations.
// ConfigAuditFixer injects the real audit.Logger adapter via WithAuditLog;
// a nil sink disables auditing without failing the mutation.
type AuditSink interface {
	WriteAudit(ctx context.Context, actor, action, resourceType, resourceID, details string) error
}

func auditWrite(sink AuditSink, ctx context.Context, actor, action, resourceType, resourceID, details string) {
	if sink == nil {
		return
	}
	if err := sink.WriteAudit(ctx, actor, action, resourceType, resourceID, details); err != nil {
		slog.Warn("audit write failed", "action", action, "resource", resourceID, "err", err)
	}
}

func auditActor(r *http.Request) string {
	if id := UserIDFromContext(r.Context()); id != "" {
		return "user:" + id
	}
	if id, _ := r.Context().Value(ctxKeyAgentID).(string); id != "" {
		return "agent:" + shortID(id)
	}
	return "anonymous"
}
