package audit

// Audit signing-key persistence (FIX_PLAN 0.7): the key lives in a 0600
// file (or KMS env), never New(nil)-per-process. Restart-stable Verify.
//
// Precedence: explicit path arg > TRACE_AUDIT_KEY_FILE > TRACE_AUDIT_KEY
// (raw hex or utf8) > ~/.trace/audit.key. *_FILE variants supported.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultAuditKeyName = "audit.key"

// LoadOrCreateKey loads the audit HMAC key from path (or default location),
// creating it with 0600 perms (dir 0700) when absent.
func LoadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		if p := os.Getenv("TRACE_AUDIT_KEY_FILE"); p != "" {
			path = p
		} else {
			home, _ := os.UserHomeDir()
			path = filepath.Join(home, ".trace", defaultAuditKeyName)
		}
	}
	if raw := os.Getenv("TRACE_AUDIT_KEY"); raw != "" {
		if b, err := hex.DecodeString(strings.TrimSpace(raw)); err == nil && len(b) >= 16 {
			return b, nil
		}
		if len(raw) >= 16 {
			return []byte(raw), nil
		}
		return nil, fmt.Errorf("TRACE_AUDIT_KEY too short (need >=16 bytes)")
	}
	if data, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(data))
		if b, err := hex.DecodeString(s); err == nil && len(b) >= 16 {
			return b, nil
		}
		if len(s) >= 16 {
			return []byte(s), nil
		}
		return nil, fmt.Errorf("audit key file %s too short", path)
	}
	key := make([]byte, signingKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate audit key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("mkdir audit key dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600); err != nil {
		return nil, fmt.Errorf("write audit key: %w", err)
	}
	return key, nil
}
