package playbook

// Approval tokens (FIX_PLAN 0.9): per-step, bound, expiring.
// Contract: {nonce, investigation_id, step_index, action, params_hash,
// approver, expiry}. TTL + escalation + approver notify. Bounded wait
// (deny-closed): waitForApproval polls with deadline, never forever.
//
// Storage: approvals table (CREATE TABLE IF NOT EXISTS, additive only)
// managed by the investigation.Manager via EnsureApprovalsTable. Tokens are
// HMAC-signed with the audit key file material conceptually, but to avoid an
// import cycle (audit never imports playbook) the token signer here uses its
// own persisted key file ~/.trace/approval.key (0600) + TRACE_APPROVAL_KEY[_FILE].

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ApprovalToken binds one approval grant to one step execution.
// Issuer notes the human approver (email/ID) in Approver.
type ApprovalToken struct {
	Nonce           string `json:"nonce"`
	InvestigationID string `json:"investigation_id"`
	StepIndex       int    `json:"step_index"`
	Action          string `json:"action"`
	ParamsHash      string `json:"params_hash"`
	Approver        string `json:"approver"`
	Expiry          string `json:"expiry"` // RFC3339
	Signature       string `json:"signature,omitempty"`
}

// ApprovalTTL is the default token lifetime.
const ApprovalTTL = 30 * time.Minute

// ApprovalWaitTimeout bounds waitForApproval (deny-closed on expiry).
const ApprovalWaitTimeout = 15 * time.Minute

// ParamsHash hashes canonical step params for token binding.
func ParamsHash(params map[string]any) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%v;", k, params[k])
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

func approvalKeyPath() string {
	if p := os.Getenv("TRACE_APPROVAL_KEY_FILE"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trace", "approval.key")
}

func loadApprovalKey() ([]byte, error) {
	if raw := os.Getenv("TRACE_APPROVAL_KEY"); raw != "" {
		if b, err := hex.DecodeString(strings.TrimSpace(raw)); err == nil && len(b) >= 16 {
			return b, nil
		}
		if len(raw) >= 16 {
			return []byte(raw), nil
		}
		return nil, fmt.Errorf("TRACE_APPROVAL_KEY too short")
	}
	path := approvalKeyPath()
	if data, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(data))
		if b, err := hex.DecodeString(s); err == nil && len(b) >= 16 {
			return b, nil
		}
		if len(s) >= 16 {
			return []byte(s), nil
		}
		return nil, fmt.Errorf("approval key file too short")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func signToken(t *ApprovalToken) error {
	key, err := loadApprovalKey()
	if err != nil {
		return err
	}
	msg := strings.Join([]string{
		t.Nonce, t.InvestigationID, fmt.Sprint(t.StepIndex),
		t.Action, t.ParamsHash, t.Approver, t.Expiry,
	}, "|")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	t.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// VerifyApprovalToken checks signature, expiry, and binding to the given
// investigation/step/action/params. Foreign or expired tokens are denied.
func VerifyApprovalToken(t *ApprovalToken, investigationID string, stepIndex int, action string, params map[string]any) error {
	if t == nil {
		return fmt.Errorf("nil approval token")
	}
	if t.InvestigationID != investigationID {
		return fmt.Errorf("token bound to investigation %s, not %s", t.InvestigationID, investigationID)
	}
	if t.StepIndex != stepIndex {
		return fmt.Errorf("token bound to step %d, not %d", t.StepIndex, stepIndex)
	}
	if t.Action != action {
		return fmt.Errorf("token bound to action %s, not %s", t.Action, action)
	}
	if want := ParamsHash(params); t.ParamsHash != want {
		return fmt.Errorf("token params_hash mismatch (params changed since approval)")
	}
	exp, err := time.Parse(time.RFC3339, t.Expiry)
	if err != nil {
		return fmt.Errorf("bad token expiry: %w", err)
	}
	if time.Now().UTC().After(exp) {
		return fmt.Errorf("approval token expired at %s", t.Expiry)
	}
	key, err := loadApprovalKey()
	if err != nil {
		return err
	}
	msg := strings.Join([]string{
		t.Nonce, t.InvestigationID, fmt.Sprint(t.StepIndex),
		t.Action, t.ParamsHash, t.Approver, t.Expiry,
	}, "|")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(t.Signature)) {
		return fmt.Errorf("invalid approval token signature")
	}
	if t.Nonce == "" || t.Approver == "" {
		return fmt.Errorf("approval token missing nonce/approver")
	}
	return nil
}

// IssueApprovalToken creates a signed token for a pending approval row.
func IssueApprovalToken(invID string, stepIndex int, action string, params map[string]any, approver string, ttl time.Duration) (*ApprovalToken, error) {
	if ttl <= 0 {
		ttl = ApprovalTTL
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	t := &ApprovalToken{
		Nonce:           hex.EncodeToString(nonce),
		InvestigationID: invID,
		StepIndex:       stepIndex,
		Action:          action,
		ParamsHash:      ParamsHash(params),
		Approver:        approver,
		Expiry:          time.Now().UTC().Add(ttl).Format(time.RFC3339),
	}
	if err := signToken(t); err != nil {
		return nil, err
	}
	return t, nil
}


// EnsureApprovalsTable creates the additive approvals table.
func EnsureApprovalsTable(ctx context.Context, exec func(ctx context.Context, query string, args ...any) error) error {
	return exec(ctx, `CREATE TABLE IF NOT EXISTS approvals (
		nonce TEXT PRIMARY KEY,
		investigation_id TEXT NOT NULL,
		step_index INTEGER NOT NULL,
		label TEXT NOT NULL DEFAULT '',
		agent TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL,
		params_hash TEXT NOT NULL,
		approver TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT NOT NULL,
		decided_at TEXT
	)`)
}

// ApprovalRow is a pending-approval listing row.
type ApprovalRow struct {
	Nonce           string `json:"nonce"`
	InvestigationID string `json:"investigation_id"`
	StepIndex       int    `json:"step_index"`
	Label           string `json:"label"`
	Agent           string `json:"agent"`
	Action          string `json:"action"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	ExpiresAt       string `json:"expires_at"`
}


// ParseApprovalToken parses a token from CLI --token JSON.
func ParseApprovalToken(s string) (*ApprovalToken, error) {
	var t ApprovalToken
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return nil, fmt.Errorf("parse approval token: %w", err)
	}
	return &t, nil
}
