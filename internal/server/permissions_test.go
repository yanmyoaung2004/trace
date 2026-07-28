package server

import (
	"context"
	"testing"
)

func TestHasPermission_Admin(t *testing.T) {
	if !HasPermission(RoleAdmin, PermAdmin) {
		t.Error("admin should have admin permission")
	}
	if !HasPermission(RoleAdmin, PermCaseWrite) {
		t.Error("admin should have case write")
	}
	if !HasPermission(RoleAdmin, PermAgentRevoke) {
		t.Error("admin should have agent revoke")
	}
}

func TestHasPermission_Analyst(t *testing.T) {
	if HasPermission(RoleAnalyst, PermAdmin) {
		t.Error("analyst should not have admin")
	}
	if !HasPermission(RoleAnalyst, PermCaseWrite) {
		t.Error("analyst should have case write")
	}
	if HasPermission(RoleAnalyst, PermAgentRevoke) {
		t.Error("analyst should not have agent revoke")
	}
	if !HasPermission(RoleAnalyst, PermInvestRead) {
		t.Error("analyst should have investigation read")
	}
}

func TestHasPermission_Viewer(t *testing.T) {
	if HasPermission(RoleViewer, PermCaseWrite) {
		t.Error("viewer should not have case write")
	}
	if !HasPermission(RoleViewer, PermCaseRead) {
		t.Error("viewer should have case read")
	}
	if HasPermission(RoleViewer, PermAgentWrite) {
		t.Error("viewer should not have agent write")
	}
}

func TestHasPermission_UnknownRole(t *testing.T) {
	if HasPermission(Role("hacker"), PermCaseRead) {
		t.Error("unknown role should have no permissions")
	}
}

func TestRoleFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "admin")
	role := RoleFromContext(ctx)
	if role != RoleAdmin {
		t.Errorf("expected admin, got %s", role)
	}
}

func TestUserIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyUserID, "user-123")
	id := UserIDFromContext(ctx)
	if id != "user-123" {
		t.Errorf("expected user-123, got %s", id)
	}
}

func TestOrgIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyOrg, "org-456")
	org := OrgIDFromContext(ctx)
	if org != "org-456" {
		t.Errorf("expected org-456, got %s", org)
	}
}

func TestScopeFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyScope, "read-only")
	scope := ScopeFromContext(ctx)
	if scope != ScopeReadOnly {
		t.Errorf("expected read-only, got %s", scope)
	}
}

func TestRolePermissions_NoMissingPermissions(t *testing.T) {
	// All roles should have at least some permissions
	for role, perms := range rolePermissions {
		if len(perms) == 0 {
			t.Errorf("role %s has no permissions", role)
		}
	}
}
