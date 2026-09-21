package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"log/slog"
)

// Auth is the shared authentication/authorization middleware for the central
// server (FIX_PLAN 0.2 + 0.3). Keys are header-only
// (Authorization: Bearer <key>); ?api_key= in the URL is rejected so keys
// never land in access logs. Failures feed an in-memory rate-limit/lockout
// guard and auth-failure metrics.
type Auth struct {
	mgr     *ServerManager
	guard   *authGuard
	metrics *serverMetrics
	audit   AuditSink
}

func newAuth(mgr *ServerManager, m *serverMetrics) *Auth {
	if m == nil {
		m = newServerMetrics()
	}
	return &Auth{
		mgr:     mgr,
		guard:   newAuthGuard(10, 5*time.Minute, 10*time.Minute),
		metrics: m,
		audit:   nil,
	}
}

// WithAuditSink attaches the audit backend (injected by ConfigAuditFixer).
func (a *Auth) WithAuditSink(s AuditSink) *Auth {
	a.audit = s
	return a
}

// bearerToken extracts a header-only bearer token. Query-string keys are
// rejected (second return false covers both missing and query-supplied).
func bearerToken(r *http.Request) (string, bool) {
	if r.URL.Query().Get("api_key") != "" {
		return "", false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if tok == "" || len(tok) > 512 {
		return "", false
	}
	return tok, true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if host == "" {
		return r.RemoteAddr
	}
	return host
}

// authenticateUser validates a user key and returns the request with identity
// (role, user ID, scope, org) bound into the context.
func (a *Auth) authenticateUser(r *http.Request) (*http.Request, bool) {
	tok, ok := bearerToken(r)
	if !ok {
		a.metrics.incAuthFailure("missing_token")
		return r, false
	}
	ip := clientIP(r)
	keyFP := hashSecret(tok)
	if len(keyFP) > 16 {
		keyFP = keyFP[:16]
	}
	if a.guard.blocked("ip:"+ip) || a.guard.blocked("key:"+keyFP) {
		a.metrics.incAuthFailure("locked_out")
		return r, false
	}
	userID, role, orgID, scope, err := a.mgr.AuthenticateOrgFull(r.Context(), tok)
	if err != nil || userID == "" {
		a.guard.fail("ip:" + ip)
		a.guard.fail("key:" + keyFP)
		a.metrics.incAuthFailure("invalid_key")
		auditWrite(a.audit, r.Context(), "anonymous", "auth.failed", "session", ip, "invalid user key")
		return r, false
	}
	a.guard.reset("ip:" + ip)
	ctx := r.Context()
	ctx = context.WithValue(ctx, ctxKeyRole, role)
	ctx = context.WithValue(ctx, ctxKeyUserID, userID)
	ctx = context.WithValue(ctx, ctxKeyScope, scope)
	if orgID != "" {
		ctx = context.WithValue(ctx, ctxKeyOrg, orgID)
	}
	return r.WithContext(ctx), true
}

// authenticateAgent validates an agent key and binds the server-known agent ID
// (plus the agent's org) into the context. The returned request is authoritative:
// handlers MUST use the ctx agent ID, never a client-supplied one.
func (a *Auth) authenticateAgent(r *http.Request) (*http.Request, bool) {
	tok, ok := bearerToken(r)
	if !ok {
		a.metrics.incAuthFailure("missing_token")
		return r, false
	}
	ip := clientIP(r)
	if a.guard.blocked("ip:" + ip) {
		a.metrics.incAuthFailure("locked_out")
		return r, false
	}
	agentID, orgID, err := a.mgr.AuthenticateAgent(r.Context(), tok)
	if err != nil || agentID == "" {
		a.guard.fail("ip:" + ip)
		a.metrics.incAuthFailure("invalid_agent_key")
		return r, false
	}
	a.guard.reset("ip:" + ip)
	ctx := context.WithValue(r.Context(), ctxKeyAgentID, agentID)
	if orgID != "" {
		ctx = context.WithValue(ctx, ctxKeyOrg, orgID)
	}
	return r.WithContext(ctx), true
}

func rejectQueryKey(a *Auth, w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Query().Get("api_key") != "" {
		// Key fingerprint only — never the key itself.
		slog.Warn("rejected API key in URL query; use Authorization header",
			"route", r.URL.Path, "ip", clientIP(r))
		a.metrics.incAuthFailure("key_in_url")
		writeAPIError(w, r, http.StatusUnauthorized,
			"unauthorized — send key via Authorization: Bearer header, not URL")
		return true
	}
	return false
}

// UserAuth gates user routes: valid user key plus the ScopeFull/ReadOnly
// method matrix (read-only keys may only use safe methods).
func (a *Auth) UserAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rejectQueryKey(a, w, r) {
			return
		}
		nr, ok := a.authenticateUser(r)
		if !ok {
			writeAPIError(w, r, http.StatusUnauthorized,
				"unauthorized — provide Authorization: Bearer <key>")
			return
		}
		r = nr
		if ScopeFromContext(r.Context()) == ScopeReadOnly &&
			r.Method != http.MethodGet && r.Method != http.MethodHead &&
			r.Method != http.MethodOptions {
			writeAPIError(w, r, http.StatusForbidden, "read-only scope: write method denied")
			return
		}
		handler(w, r)
	}
}

// AgentAuth gates fleet-protocol routes: valid agent key only, identity from ctx.
func (a *Auth) AgentAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rejectQueryKey(a, w, r) {
			return
		}
		nr, ok := a.authenticateAgent(r)
		if !ok {
			writeAPIError(w, r, http.StatusUnauthorized,
				"unauthorized — provide Authorization: Bearer <agent-key>")
			return
		}
		handler(w, nr)
	}
}

// FleetOrUser accepts either a fleet agent key or a user key carrying userPerm
// ("" skips the permission check — any authenticated caller). Agent identity,
// when present, is ctx-bound; userPerm-gated branches MUST additionally check
// HasPermission-equivalent logic via the ctx role when serving other agents'
// data (see handleEDREvents).
func (a *Auth) FleetOrUser(userPerm Permission, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rejectQueryKey(a, w, r) {
			return
		}
		if nr, ok := a.authenticateAgent(r); ok {
			handler(w, nr)
			return
		}
		nr, ok := a.authenticateUser(r)
		if !ok {
			writeAPIError(w, r, http.StatusUnauthorized,
				"unauthorized — provide Authorization: Bearer <agent-key or user-key>")
			return
		}
		if userPerm != "" && !HasPermission(RoleFromContext(nr.Context()), userPerm) {
			writeAPIError(w, r, http.StatusForbidden, "insufficient permissions")
			return
		}
		if userPerm != "" && ScopeFromContext(nr.Context()) == ScopeReadOnly &&
			r.Method != http.MethodGet && r.Method != http.MethodHead &&
			r.Method != http.MethodOptions {
			writeAPIError(w, r, http.StatusForbidden, "read-only scope: write method denied")
			return
		}
		handler(w, nr)
	}
}

// RequirePerm gates a user route on a specific permission (plus UserAuth).
func (a *Auth) RequirePerm(perm Permission, handler http.HandlerFunc) http.HandlerFunc {
	return a.UserAuth(func(w http.ResponseWriter, r *http.Request) {
		if !HasPermission(RoleFromContext(r.Context()), perm) {
			writeAPIError(w, r, http.StatusForbidden, "insufficient permissions")
			return
		}
		handler(w, r)
	})
}

// validRole reports whether s is a known role name.
func validRole(s string) bool {
	switch Role(s) {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	}
	return false
}

// ctxAgentID returns the ctx-bound agent ID, or "" when the caller is not an agent.
func ctxAgentID(r *http.Request) string {
	id, _ := r.Context().Value(ctxKeyAgentID).(string)
	return id
}
