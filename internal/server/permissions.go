package server

import (
	"context"
)

// Permission defines a granular action that can be authorized.
type Permission string

const (
	PermCaseRead     Permission = "case:read"
	PermCaseWrite    Permission = "case:write"
	PermCaseDelete   Permission = "case:delete"
	PermInvestRead   Permission = "investigation:read"
	PermInvestWrite  Permission = "investigation:write"
	PermAgentRead    Permission = "agent:read"
	PermAgentWrite   Permission = "agent:write"
	PermAgentRevoke  Permission = "agent:revoke"
	PermUserRead     Permission = "user:read"
	PermUserWrite    Permission = "user:write"
	PermCompliance   Permission = "compliance:read"
	PermAdmin        Permission = "admin"
	PermAuditRead    Permission = "audit:read"
)

// Role defines a named set of permissions.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// rolePermissions maps roles to their allowed permissions.
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermCaseRead, PermCaseWrite, PermCaseDelete,
		PermInvestRead, PermInvestWrite,
		PermAgentRead, PermAgentWrite, PermAgentRevoke,
		PermUserRead, PermUserWrite,
		PermCompliance,
		PermAdmin,
		PermAuditRead,
	},
	RoleAnalyst: {
		PermCaseRead, PermCaseWrite,
		PermInvestRead, PermInvestWrite,
		PermAgentRead,
		PermCompliance,
	},
	RoleViewer: {
		PermCaseRead,
		PermInvestRead,
		PermAgentRead,
		PermCompliance,
		PermAuditRead,
	},
}

// HasPermission checks if a role has the given permission.
func HasPermission(role Role, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}

// APIKeyScope defines the scope of an API key.
type APIKeyScope string

const (
	ScopeFull     APIKeyScope = "full"
	ScopeReadOnly APIKeyScope = "read-only"
)

// Context key types.
type ctxKey string

const (
	ctxKeyRole     ctxKey = "role"
	ctxKeyUserID   ctxKey = "user_id"
	ctxKeyOrg      ctxKey = "org_id"
	ctxKeyAgentID  ctxKey = "agent_id"
	ctxKeyScope    ctxKey = "scope"
)

// RoleFromContext extracts the role from a request context.
func RoleFromContext(ctx context.Context) Role {
	r, _ := ctx.Value(ctxKeyRole).(string)
	return Role(r)
}

// UserIDFromContext extracts the user ID from a request context.
func UserIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyUserID).(string)
	return id
}

// OrgIDFromContext extracts the org ID from a request context.
func OrgIDFromContext(ctx context.Context) string {
	org, _ := ctx.Value(ctxKeyOrg).(string)
	return org
}

// ScopeFromContext extracts the API key scope from a request context.
func ScopeFromContext(ctx context.Context) APIKeyScope {
	s, _ := ctx.Value(ctxKeyScope).(string)
	return APIKeyScope(s)
}
