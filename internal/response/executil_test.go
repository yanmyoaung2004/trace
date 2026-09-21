package response_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/response"
)

func TestValidateIPBypass(t *testing.T) {
	bad := []string{
		"",
		"1.2.3.4; rm -rf /",
		"1.2.3.4 && id",
		"1.2.3.4 | id",
		"$(id)",
		"`id`",
		"1.2.3.4\n8.8.8.8",
		"1.2.3.4\r\n evil",
		"999.999.999.999",
		"../etc/passwd",
		"1.2.3.4$HOME",
		"'1.2.3.4'",
		"(1.2.3.4)",
	}
	for _, s := range bad {
		if _, err := response.ValidateIP(s); err == nil {
			t.Errorf("ValidateIP(%q) accepted, want error", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "::1"} {
		if _, err := response.ValidateIP(s); err != nil {
			t.Errorf("ValidateIP(%q) rejected: %v", s, err)
		}
	}
}

func TestValidateIPAllowlist(t *testing.T) {
	t.Setenv("TRACE_RESPONSE_IP_ALLOWLIST", "10.0.0.0/8")
	if _, err := response.ValidateIP("10.1.2.3"); err != nil {
		t.Errorf("allowlisted IP rejected: %v", err)
	}
	if _, err := response.ValidateIP("192.168.1.1"); err == nil {
		t.Error("non-allowlisted IP accepted, want error")
	}
}

func TestValidatePIDStringBypass(t *testing.T) {
	bad := []string{"", "abc", "-1", "0", "1;rm", "12\n34", "$(1)", "`1`", "1 2", "4194305", "99999999"}
	for _, s := range bad {
		if _, err := response.ValidatePIDString(s); err == nil {
			t.Errorf("ValidatePIDString(%q) accepted, want error", s)
		}
	}
	if _, err := response.ValidatePIDString("1"); err != nil {
		t.Errorf("ValidatePIDString(1) rejected: %v", err)
	}
}

func TestValidateServiceNameBypass(t *testing.T) {
	bad := []string{
		"", "foo;bar", "a&&b", "a|b", "a$(b)", "a`b`", "a/b", "a\\b",
		"a b", "a\nb", strings.Repeat("a", 65),
	}
	for _, s := range bad {
		if err := response.ValidateServiceName(s); err == nil {
			t.Errorf("ValidateServiceName(%q) accepted, want error", s)
		}
	}
	for _, s := range []string{"BITS", "my-service_1.2", "a"} {
		if err := response.ValidateServiceName(s); err != nil {
			t.Errorf("ValidateServiceName(%q) rejected: %v", s, err)
		}
	}
}

func TestValidateProcessNameBypass(t *testing.T) {
	for _, s := range []string{"", "foo;bar", "a/b", "a\\b", "a$(b)", "x`y`", "a b", "a\nb"} {
		if err := response.ValidateProcessName(s); err == nil {
			t.Errorf("ValidateProcessName(%q) accepted, want error", s)
		}
	}
	if err := response.ValidateProcessName("foo.exe"); err != nil {
		t.Errorf("ValidateProcessName(foo.exe) rejected: %v", err)
	}
}

func TestValidateFilePathBypass(t *testing.T) {
	for _, s := range []string{"", "a;b", "a$(b)", "a`b`", "x\ny", "a|b", "a&b"} {
		if err := response.ValidateFilePath(s); err == nil {
			t.Errorf("ValidateFilePath(%q) accepted, want error", s)
		}
	}
	if err := response.ValidateFilePath(filepath.Join(t.TempDir(), "ok.bin")); err != nil {
		t.Errorf("ValidateFilePath(valid) rejected: %v", err)
	}
}

func TestConfineToRoot(t *testing.T) {
	root := t.TempDir()
	if _, err := response.ConfineToRoot(root, "../escape"); err == nil {
		t.Error("ConfineToRoot(../escape) accepted, want error")
	}
	// Absolute path outside root (portable: sibling of the temp root).
	outsideAbs := filepath.Join(filepath.Dir(root), "outside-escape.bin")
	if _, err := response.ConfineToRoot(root, outsideAbs); err == nil {
		t.Errorf("ConfineToRoot(%q) accepted, want error", outsideAbs)
	}
	ok, err := response.ConfineToRoot(root, "sub/dir/file.bin")
	if err != nil {
		t.Fatalf("ConfineToRoot(valid) rejected: %v", err)
	}
	rel, _ := filepath.Rel(root, ok)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Errorf("ConfineToRoot escaped root: %s", ok)
	}

	// Symlinked destination is rejected (O_NOFOLLOW semantics).
	outside := filepath.Join(t.TempDir(), "outside.bin")
	os.WriteFile(outside, []byte("x"), 0644)
	link := filepath.Join(root, "link.bin")
	if err := os.Symlink(outside, link); err == nil {
		if _, err := response.ConfineToRoot(root, link); err == nil {
			t.Error("ConfineToRoot(symlink) accepted, want error")
		}
		if err := response.CheckSymlinkOrDevice(link); err == nil {
			t.Error("CheckSymlinkOrDevice(symlink) accepted, want error")
		}
	}

	// Symlinked parent directory is rejected.
	realDir := filepath.Join(root, "real")
	os.MkdirAll(realDir, 0755)
	parentLink := filepath.Join(root, "parentlink")
	if err := os.Symlink(realDir, parentLink); err == nil {
		if _, err := response.ConfineToRoot(root, filepath.Join(parentLink, "f.bin")); err == nil {
			t.Error("ConfineToRoot(symlinked parent) accepted, want error")
		}
	}
}

func TestArgvConstructorsHaveNoShell(t *testing.T) {
	ip, err := response.ValidateIP("10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	a, inv := response.BlockIPArgv(ip)
	argvSets := [][]string{a, inv,
		response.KillPIDArgv(123),
		response.TaskkillPIDArgv(123),
		response.PkillArgv("foo.exe"),
		response.TaskkillNameArgv("foo.exe"),
		response.SystemctlRestartArgv("BITS"),
		response.LaunchctlRestartArgv("svc"),
		response.ScStopArgv("BITS"),
		response.ScStartArgv("BITS"),
	}
	mv, mi := response.MoveArgv("/a", "/b")
	argvSets = append(argvSets, mv, mi)
	if mv[0] != "__rename__" || mv[1] != "/a" || mv[2] != "/b" {
		t.Errorf("MoveArgv broken: %v", mv)
	}
	if mi[0] != "__rename__" || mi[1] != "/b" || mi[2] != "/a" {
		t.Errorf("MoveArgv inverse broken: %v", mi)
	}
	for _, argv := range argvSets {
		if len(argv) == 0 {
			t.Error("empty argv from constructor")
			continue
		}
		for _, el := range argv[1:] {
			if strings.ContainsAny(el, ";|&$`\"\n\r'(){}<>!#~*?") && argv[0] != "__rename__" {
				t.Errorf("argv element %q in %v looks like shell", el, argv)
			}
		}
	}
	if got := response.KillPIDArgv(9); len(got) != 3 || got[0] != "kill" || got[2] != "9" {
		t.Errorf("KillPIDArgv = %v", got)
	}
	if got := response.SystemctlRestartArgv("x"); len(got) != 3 || got[0] != "systemctl" {
		t.Errorf("SystemctlRestartArgv = %v", got)
	}
}

func TestStoredCmdRoundTripAndLegacy(t *testing.T) {
	ip, _ := response.ValidateIP("10.0.0.6")
	argv, inv := response.BlockIPArgv(ip)
	stored := response.EncodeArgv(argv, inv)
	sc, ok := response.DecodeStored(stored)
	if !ok || len(sc.Argv) == 0 || sc.Argv[0] != argv[0] {
		t.Errorf("round trip failed: %v %v", sc, ok)
	}
	for _, legacy := range []string{"iptables -D INPUT -s 1.2.3.4 -j DROP", "mv \"a\" \"b\"", "plain string"} {
		if _, ok := response.DecodeStored(legacy); ok {
			t.Errorf("DecodeStored(%q) accepted legacy string", legacy)
		}
		if !response.IsLegacyRollback(legacy) {
			t.Errorf("IsLegacyRollback(%q) = false, want true", legacy)
		}
	}
	for _, s := range []string{"", "N/A", "N/A (process cannot be unkilled)"} {
		if response.IsLegacyRollback(s) {
			t.Errorf("IsLegacyRollback(%q) = true, want false", s)
		}
	}
}

func TestRunScriptDeniedByDefault(t *testing.T) {
	t.Setenv("TRACE_RESPONSE_RUN_SCRIPT_ENABLED", "")
	params := map[string]any{"script": "echo hi"}
	if err := response.CheckRunScriptGate(params); !errors.Is(err, response.ErrRunScriptDenied) {
		t.Errorf("gate = %v, want ErrRunScriptDenied", err)
	}
	// Server agent surface denies too.
	ag := setupResponse(t)
	out, err := ag.Execute(context.Background(), map[string]any{"action": "run_script", "script": "echo hi"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(strings.ToLower(msg), "denied") {
		t.Errorf("run_script output = %v, want denial", out)
	}
}

func TestRunScriptGateApproval(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.sig")
	os.WriteFile(policy, []byte("signed"), 0600)
	t.Setenv("TRACE_RESPONSE_RUN_SCRIPT_ENABLED", "true")
	t.Setenv("TRACE_RESPONSE_RUN_SCRIPT_POLICY", policy)

	// Missing token denies closed.
	if err := response.CheckRunScriptGate(map[string]any{}); err == nil {
		t.Error("gate without token accepted, want error")
	}
	// Missing policy path denies.
	t.Setenv("TRACE_RESPONSE_RUN_SCRIPT_POLICY", filepath.Join(t.TempDir(), "missing.sig"))
	fresh := map[string]any{
		"approval_nonce": "n", "approver": "a",
		"approval_expiry": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}
	if err := response.CheckRunScriptGate(fresh); err == nil {
		t.Error("gate without policy file accepted, want error")
	}
	t.Setenv("TRACE_RESPONSE_RUN_SCRIPT_POLICY", policy)
	// Expired token denies.
	expired := map[string]any{
		"approval_nonce": "n", "approver": "a",
		"approval_expiry": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}
	if err := response.CheckRunScriptGate(expired); err == nil {
		t.Error("gate with expired token accepted, want error")
	}
	// Fresh token passes the gate (execution itself is still refused
	// elsewhere; the gate only answers "authorized?").
	if err := response.CheckRunScriptGate(fresh); err != nil {
		t.Errorf("gate with fresh token denied: %v", err)
	}
}

func TestCheckChainRejected(t *testing.T) {
	if err := response.CheckChainRejected(nil); err != nil {
		t.Errorf("nil params rejected: %v", err)
	}
	if err := response.CheckChainRejected(map[string]any{"type": "x"}); err != nil {
		t.Errorf("plain params rejected: %v", err)
	}
	if err := response.CheckChainRejected(map[string]any{"chain": []any{"kill_process"}}); !errors.Is(err, response.ErrChainRejected) {
		t.Errorf("chain = %v, want ErrChainRejected", err)
	}
}

func TestRunArgvRenameAndEmpty(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	os.WriteFile(src, []byte("data"), 0644)
	if _, err := response.RunArgv(context.Background(), []string{"__rename__", src, dst}); err != nil {
		t.Fatalf("rename argv failed: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("dst missing after rename argv: %v", err)
	}
	if _, err := response.RunArgv(context.Background(), nil); err == nil {
		t.Error("empty argv accepted, want error")
	}
}

func TestRollbackMarksLegacyUnexecutable(t *testing.T) {
	ag := setupResponse(t)
	ctx := context.Background()
	// Seed a legacy string row directly (pre-0.1 shape).
	dbh := testDBHandle(t, ag)
	id := "legacy-row-1"
	_, err := dbh.Exec(`INSERT INTO response_actions (id, investigation_id, action_name, target, status, command, output, rollback_command, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "", "block_ip", "10.0.0.9", "executed", "iptables -A INPUT -s 10.0.0.9 -j DROP", "", "iptables -D INPUT -s 10.0.0.9 -j DROP", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	out, err := ag.Execute(ctx, map[string]any{"action": "rollback", "action_id": id})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out["status"] != "legacy_unexecutable" {
		t.Errorf("rollback status = %v, want legacy_unexecutable", out)
	}
}

// testDBHandle exposes the agent's *sql.DB for seeding legacy rows.
// The Agent keeps its handle private; the test DB file is reachable only
// through a fresh handle to the same path. Since setupResponse uses a
// temp dir we cannot reopen the same file, so instead this helper reports
// a skip-free path: it opens a second in-test DB is NOT usable. To keep
// the test hermetic we store the handle at construction time.
func testDBHandle(t *testing.T, ag *response.Agent) *sql.DB {
	t.Helper()
	dbh := ag.TestDB()
	if dbh == nil {
		t.Fatal("agent has no test DB handle")
	}
	return dbh
}
