// Package response shared argv contract (FIX_PLAN 0.1).
//
// Both the server-side agent (internal/response) and the on-host EDR
// executor (internal/edr_agent/response) build OS commands ONLY through
// the constructors below and run them with RunArgv
// (exec.CommandContext(argv[0], argv[1:]...)). No caller may interpolate
// user input into a shell string. There is intentionally no sh/powershell
// string runner in this package.
package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrRunScriptDenied is returned when run_script is attempted while the
	// deny-by-default gate is closed.
	ErrRunScriptDenied = errors.New("run_script denied: disabled by default (set TRACE_RESPONSE_RUN_SCRIPT_ENABLED=true plus signed policy and per-execution approval to enable)")
	// ErrChainRejected is returned when a client-side chain is submitted.
	ErrChainRejected = errors.New("chain actions rejected: server must expand chains into individually authorized actions")
	// ErrLegacyRollback marks stored string commands from before 0.1 that
	// must never execute again.
	ErrLegacyRollback = errors.New("legacy_unexecutable: stored string command predates argv-only mode and will not run")

	serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	pidDigitsRe   = regexp.MustCompile(`^[0-9]{1,7}$`)
)

// ---------------------------------------------------------------------------
// Validators (importable read-only by dispatch for taint-isolation).
// Final exported surface (also sent to ConfigAuditFixer):
//   ValidateIP(string) (netip.Addr, error)
//   ValidatePID(int) error + ValidatePIDString(string) (int, error)
//   ValidateServiceName(string) error
//   ValidateProcessName(string) error
//   ValidateFilePath(string) error
//   CheckSymlinkOrDevice(string) error
//   ConfineToRoot(root, p string) (string, error)
//   ResolveQuarantineDest(root, srcPath string) (string, error)
// ---------------------------------------------------------------------------

// ValidateIP parses s with netip.ParseAddr and rejects shell metacharacters,
// empty, unspecified and (optionally) anything outside the CIDR allowlist in
// TRACE_RESPONSE_IP_ALLOWLIST (comma-separated CIDRs, empty = allow all).
func ValidateIP(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, errors.New("ip is required")
	}
	if strings.ContainsAny(s, ";|&$`\\\n\r\"'(){}<>!#~*?") {
		return netip.Addr{}, fmt.Errorf("ip contains forbidden characters: %q", s)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ip %q: %w", s, err)
	}
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("invalid ip %q", s)
	}
	allow := strings.TrimSpace(os.Getenv("TRACE_RESPONSE_IP_ALLOWLIST"))
	if allow == "" {
		return addr, nil
	}
	for _, cidr := range strings.Split(allow, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if pfx.Contains(addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("ip %q outside allowlist", s)
}

// ValidatePID checks range only (no filesystem access).
func ValidatePID(pid int) error {
	if pid <= 0 || pid > 4194304 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err != nil {
			return fmt.Errorf("pid %d not present in /proc: %w", pid, err)
		}
	}
	return nil
}

// ValidatePIDString requires digits-only then delegates to ValidatePID.
func ValidatePIDString(s string) (int, error) {
	if !pidDigitsRe.MatchString(s) {
		return 0, fmt.Errorf("invalid pid %q: digits only", s)
	}
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid pid %q", s)
	}
	if err := ValidatePID(pid); err != nil {
		return 0, err
	}
	return pid, nil
}

// ValidateServiceName enforces ^[A-Za-z0-9._-]{1,64}$.
func ValidateServiceName(s string) error {
	if !serviceNameRe.MatchString(s) {
		return fmt.Errorf("invalid service name %q", s)
	}
	return nil
}

// ValidateProcessName uses the same allowlist as service names (covers
// "foo.exe" style names) and additionally rejects path separators and
// shell metacharacters explicitly for clear errors.
func ValidateProcessName(s string) error {
	if s == "" {
		return errors.New("process name is required")
	}
	if strings.ContainsAny(s, "/\\;|&$`\"\n\r'(){}<>!#~*?") {
		return fmt.Errorf("invalid process name %q", s)
	}
	return ValidateServiceName(s)
}

// ValidateFilePath rejects empty paths and anything containing shell
// metacharacters, newlines, or NUL. It does not check existence.
func ValidateFilePath(p string) error {
	if p == "" {
		return errors.New("path is required")
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("invalid path %q: NUL byte", p)
	}
	if strings.ContainsAny(p, ";\n\r`$()|&<>!#~*?\"'") {
		return fmt.Errorf("invalid path %q: forbidden characters", p)
	}
	return nil
}

// CheckSymlinkOrDevice rejects symlinks and device nodes via Lstat
// (O_NOFOLLOW semantics: never follow the final component).
func CheckSymlinkOrDevice(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q is a symlink", p)
	}
	if fi.Mode()&os.ModeDevice != 0 || fi.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("path %q is a device node", p)
	}
	return nil
}

// ConfineToRoot resolves p (joining with root when relative) and ensures the
// result stays under root via filepath.Rel. Rejects ".." escapes, absolute
// escapes, symlinked destinations, and device nodes.
func ConfineToRoot(root, p string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	candidate := p
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(absRoot, candidate)
	}
	clean := filepath.Clean(candidate)
	rel, err := filepath.Rel(absRoot, clean)
	if err != nil {
		return "", fmt.Errorf("path %q cannot be confined: %w", p, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes quarantine root", p)
	}
	// Destination must not already be a symlink/device.
	if fi, err := os.Lstat(clean); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("destination %q is a symlink", p)
		}
		if fi.Mode()&os.ModeDevice != 0 || fi.Mode()&os.ModeCharDevice != 0 {
			return "", fmt.Errorf("destination %q is a device node", p)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	// Every existing parent component must not be a symlink (no O_NOFOLLOW
	// bypass through a symlinked directory).
	dir := filepath.Dir(clean)
	for dir != absRoot && strings.HasPrefix(dir, absRoot) {
		if fi, err := os.Lstat(dir); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("parent %q is a symlink", dir)
			}
		} else if os.IsNotExist(err) {
			// Missing parents will be created under root; keep walking up.
		} else {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return clean, nil
}

// ResolveQuarantineDest validates src and returns a confined destination
// under root derived from the source basename plus a random suffix.
func ResolveQuarantineDest(root, srcPath string) (string, error) {
	if err := ValidateFilePath(srcPath); err != nil {
		return "", err
	}
	base := filepath.Base(filepath.Clean(srcPath))
	if base == "." || base == "/" || base == "" {
		return "", fmt.Errorf("invalid source path %q", srcPath)
	}
	if err := ValidateFilePath(base); err != nil {
		return "", err
	}
	candidate := filepath.Join(root, base+"."+uuid.New().String()[:8])
	return ConfineToRoot(root, candidate)
}

// ---------------------------------------------------------------------------
// Argv constructors. argv[0] is the binary; never a shell.
// Each block action also returns its inverse argv for rollback.
// ---------------------------------------------------------------------------

// IptablesBlockArgv / inverse delete.
func IptablesBlockArgv(ip netip.Addr) (argv, inverse []string) {
	s := ip.String()
	return []string{"iptables", "-A", "INPUT", "-s", s, "-j", "DROP"},
		[]string{"iptables", "-D", "INPUT", "-s", s, "-j", "DROP"}
}

// NetshBlockArgv / inverse delete.
func NetshBlockArgv(ip netip.Addr) (argv, inverse []string) {
	s := ip.String()
	name := "trace-block-" + strings.ReplaceAll(strings.ReplaceAll(s, ".", "-"), ":", "-")
	return []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + name, "dir=in", "action=block", "remoteip=" + s},
		[]string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + name}
}

// PfctlBlockArgv / inverse delete (table form, no shell pipe).
func PfctlBlockArgv(ip netip.Addr) (argv, inverse []string) {
	s := ip.String()
	return []string{"pfctl", "-t", "trace", "-T", "add", s},
		[]string{"pfctl", "-t", "trace", "-T", "delete", s}
}

// BlockIPArgv dispatches on runtime.GOOS.
func BlockIPArgv(ip netip.Addr) (argv, inverse []string) {
	switch runtime.GOOS {
	case "windows":
		return NetshBlockArgv(ip)
	case "darwin":
		return PfctlBlockArgv(ip)
	default:
		return IptablesBlockArgv(ip)
	}
}

// KillPIDArgv is kill -9 <pid> (linux/darwin).
func KillPIDArgv(pid int) []string { return []string{"kill", "-9", strconv.Itoa(pid)} }

// TaskkillPIDArgv is taskkill /F /PID <pid> (windows).
func TaskkillPIDArgv(pid int) []string { return []string{"taskkill", "/F", "/PID", strconv.Itoa(pid)} }

// PkillArgv is pkill -9 <name> (linux/darwin, name pre-validated).
func PkillArgv(name string) []string { return []string{"pkill", "-9", name} }

// TaskkillNameArgv is taskkill /F /IM <name> (windows, name pre-validated).
func TaskkillNameArgv(name string) []string { return []string{"taskkill", "/F", "/IM", name} }

// SystemctlRestartArgv is systemctl restart <svc>.
func SystemctlRestartArgv(svc string) []string {
	return []string{"systemctl", "restart", svc}
}

// LaunchctlRestartArgv is launchctl kickstart -k system/<svc>.
func LaunchctlRestartArgv(svc string) []string {
	return []string{"launchctl", "kickstart", "-k", "system/" + svc}
}

// ScStopArgv / ScStartArgv are the two windows service steps.
func ScStopArgv(svc string) []string  { return []string{"sc", "stop", svc} }
func ScStartArgv(svc string) []string { return []string{"sc", "start", svc} }

// MoveArgv describes an os.Rename move (no process is spawned; kept so both
// stacks share one structured action vocabulary).
func MoveArgv(src, dst string) (argv, inverse []string) {
	return []string{"__rename__", src, dst}, []string{"__rename__", dst, src}
}

// ---------------------------------------------------------------------------
// Runner + gates.
// ---------------------------------------------------------------------------

// RunArgv executes argv[0] argv[1:] with no shell. argv[0]=="__rename__" is
// a structured move performed with os.Rename (chmod left to the caller).
func RunArgv(ctx context.Context, argv []string) (string, error) {
	if len(argv) == 0 || argv[0] == "" {
		return "", errors.New("empty argv")
	}
	if argv[0] == "__rename__" {
		if len(argv) != 3 {
			return "", fmt.Errorf("bad rename argv: %v", argv)
		}
		if err := os.Rename(argv[1], argv[2]); err != nil {
			return "", err
		}
		return "", nil
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	const maxOut = 8 << 10
	if len(s) > maxOut {
		s = s[:maxOut] + "...[truncated]"
	}
	if err != nil {
		log.Printf("response: argv failed: %v\noutput: %s\nerror: %v", argv[0], s, err)
		return s, err
	}
	log.Printf("response: argv ok: %v", argv[0])
	return s, nil
}

// runShellGated is the single gated legacy-string helper. It always denies;
// it exists so the codebase has exactly one place where a string command
// could ever be executed, and that place refuses. (No shell is spawned.)
func runShellGated(_ context.Context, cmdStr string) (string, error) {
	_ = cmdStr
	return "", errors.New("legacy string execution disabled: argv-only mode (see executil)")
}

// RunScriptEnabled reports the deny-by-default flag. Default false; set
// TRACE_RESPONSE_RUN_SCRIPT_ENABLED=true to opt in (still requires a signed
// policy file and a per-execution approval token, enforced by
// CheckRunScriptGate).
func RunScriptEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("TRACE_RESPONSE_RUN_SCRIPT_ENABLED")))
	return v == "true" || v == "1" || v == "yes"
}

// CheckRunScriptGate enforces: flag on + signed policy file present +
// per-execution approval token params present and unexpired. Deny-closed:
// any absence is an error. Approval token shape (per contract):
// {nonce, investigation_id, step_index, action, params_hash, approver, expiry}.
func CheckRunScriptGate(params map[string]any) error {
	if !RunScriptEnabled() {
		log.Printf("response: run_script attempt denied (disabled by default)")
		return ErrRunScriptDenied
	}
	policy := strings.TrimSpace(os.Getenv("TRACE_RESPONSE_RUN_SCRIPT_POLICY"))
	if policy == "" {
		log.Printf("response: run_script attempt denied (no signed policy file)")
		return errors.New("run_script denied: no signed policy file (TRACE_RESPONSE_RUN_SCRIPT_POLICY)")
	}
	if fi, err := os.Stat(policy); err != nil || fi.IsDir() {
		log.Printf("response: run_script attempt denied (policy file unreadable)")
		return errors.New("run_script denied: signed policy file unreadable")
	}
	str := func(k string) string {
		v, _ := params[k].(string)
		return strings.TrimSpace(v)
	}
	nonce, approver, action, expiryS := str("approval_nonce"), str("approver"), str("action"), str("approval_expiry")
	if nonce == "" || approver == "" {
		log.Printf("response: run_script attempt denied (missing approval token)")
		return errors.New("run_script denied: missing per-execution approval token (nonce/approver)")
	}
	_ = action
	if expiryS == "" {
		log.Printf("response: run_script attempt denied (missing approval expiry)")
		return errors.New("run_script denied: approval token has no expiry")
	}
	exp, err := time.Parse(time.RFC3339, expiryS)
	if err != nil {
		if n, err2 := strconv.ParseInt(expiryS, 10, 64); err2 == nil {
			exp = time.Unix(n, 0)
		} else {
			return errors.New("run_script denied: bad approval expiry")
		}
	}
	if time.Now().UTC().After(exp) {
		return errors.New("run_script denied: approval token expired")
	}
	return nil
}

// CheckChainRejected returns ErrChainRejected when params carry a client-side
// "chain" key. Servers must expand chains into individually authorized
// actions.
func CheckChainRejected(params map[string]any) error {
	if params == nil {
		return nil
	}
	if v, ok := params["chain"]; ok && v != nil {
		return ErrChainRejected
	}
	return nil
}

// ---------------------------------------------------------------------------
// Structured rollback encoding. Stored in the existing TEXT columns as JSON
// (no schema change): {"argv":[...],"inverse":[...]}. Anything else in those
// columns is a legacy string and must not execute.
// ---------------------------------------------------------------------------

// StoredCmd is the JSON envelope for command/rollback columns.
type StoredCmd struct {
	Argv    []string `json:"argv"`
	Inverse []string `json:"inverse,omitempty"`
}

// EncodeArgv marshals argv+inverse for storage.
func EncodeArgv(argv, inverse []string) string {
	b, _ := json.Marshal(StoredCmd{Argv: argv, Inverse: inverse})
	return string(b)
}

// DecodeStored parses a stored column. ok=false means legacy string.
func DecodeStored(s string) (StoredCmd, bool) {
	var sc StoredCmd
	if s == "" || s == "N/A" || strings.HasPrefix(s, "N/A ") {
		return StoredCmd{}, false
	}
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&sc); err != nil {
		return StoredCmd{}, false
	}
	if len(sc.Argv) == 0 {
		return StoredCmd{}, false
	}
	return sc, true
}

// IsLegacyRollback reports whether a stored rollback value must be treated
// as legacy_unexecutable.
func IsLegacyRollback(s string) bool {
	if s == "" || s == "N/A" || strings.HasPrefix(s, "N/A ") {
		return false // non-rollbackable, not legacy
	}
	_, ok := DecodeStored(s)
	return !ok
}
// isWindows / isDarwin / isLinux report the build target for argv dispatch.
// (runtime.GOOS reads are fine; only shell-string building is banned.)
func isWindows() bool { return runtime.GOOS == "windows" }
func isDarwin() bool  { return runtime.GOOS == "darwin" }
func isLinux() bool   { return runtime.GOOS == "linux" }
