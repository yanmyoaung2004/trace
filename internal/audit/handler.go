package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// ctx keys for request wiring (shared contract: reqID string).
type ctxKey string

const (
	// CtxKeyRequestID carries the request ID (reqID string contract).
	CtxKeyRequestID ctxKey = "request_id"
	// CtxKeyActor carries the actor ID from auth ctx.
	CtxKeyActor ctxKey = "actor_id"
	// CtxKeyTenant carries TenantID/org_id from auth ctx (never defaulted).
	CtxKeyTenant ctxKey = "tenant_id"
)

// RequestIDFromCtx returns the request ID or "".
func RequestIDFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(CtxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// ActorFromCtx returns the actor ID or "anonymous".
func ActorFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(CtxKeyActor).(string); ok && v != "" {
		return v
	}
	return "anonymous"
}

// TenantFromCtx returns the tenant ID or "" (never defaults: callers that
// require tenancy must reject "").
func TenantFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(CtxKeyTenant).(string); ok {
		return v
	}
	return ""
}

// WithRequestID attaches a request ID to ctx.
func WithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, CtxKeyRequestID, reqID)
}

// Audit writes a single audit row for a mutation. Thin wrapper over
// Logger.Write so callsites stay one line. Details is marshalled via
// MarshalDetails; callers MUST pre-redact secrets (see Redact helper in
// internal/audit/redact.go).
func Audit(ctx context.Context, l *Logger, actor, action, resourceType, resourceID string, details any) error {
	if l == nil {
		return nil // audit disabled: never block the mutation
	}
	var d string
	switch v := details.(type) {
	case nil:
		d = "{}"
	case string:
		d = v
	default:
		d = MarshalDetails(v)
	}
	return l.Write(ctx, Entry{
		ActorID:      actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      d,
	})
}

// NewHTTPHandler serves GET /api/v1/audit with actor/resource/action/time
// filters. Query params: actor, resource_type, resource_id, action, since,
// until, limit (max 1000), cursor (last seen id for pagination).
// actorFn extracts the display actor for the envelope (not authority).
func NewHTTPHandler(logger *Logger, actorFn func(r *http.Request) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed", "")
			return
		}
		if logger == nil {
			writeErr(w, http.StatusNotImplemented, "audit log unavailable", reqIDOf(r))
			return
		}
		q := r.URL.Query()
		f := QueryFilter{
			ActorID:      q.Get("actor"),
			ResourceType: q.Get("resource_type"),
			ResourceID:   q.Get("resource_id"),
			Action:       q.Get("action"),
			Since:        q.Get("since"),
			Until:        q.Get("until"),
		}
		if lim := q.Get("limit"); lim != "" {
			n, err := strconv.Atoi(lim)
			if err != nil || n <= 0 {
				writeErr(w, http.StatusBadRequest, "invalid limit", reqIDOf(r))
				return
			}
			if n > 1000 {
				n = 1000
			}
			f.Limit = n
		}
		if cur := q.Get("cursor"); cur != "" {
			id, err := strconv.ParseInt(cur, 10, 64)
			if err != nil || id < 0 {
				writeErr(w, http.StatusBadRequest, "invalid cursor", reqIDOf(r))
				return
			}
			f.Cursor = id
		}
		entries, err := logger.Query(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "audit query failed", reqIDOf(r))
			return
		}
		actor := ""
		if actorFn != nil {
			actor = actorFn(r)
		}
		nextCursor := ""
		if len(entries) > 0 {
			nextCursor = strconv.FormatInt(entries[len(entries)-1].ID, 10)
		}
		writeOK(w, map[string]any{
			"entries":     entries,
			"next_cursor": nextCursor,
			"actor":       actor,
		}, reqIDOf(r))
	}
}

func reqIDOf(r *http.Request) string {
	if v := r.Context().Value(CtxKeyRequestID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return r.Header.Get("X-Request-ID")
}

func writeOK(w http.ResponseWriter, data any, reqID string) {
	w.Header().Set("Content-Type", "application/json")
	payload := map[string]any{"data": data, "error": "", "code": 200, "request_id": reqID}
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, msg, reqID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "error": msg, "code": code, "request_id": reqID})
}
