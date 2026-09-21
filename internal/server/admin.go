package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"github.com/yanmyoaung2004/trace/internal/storage/metrics"
)

// Admin/serve/update surface (FIX_PLAN 0.2 + 0.3 + 1.5).
//
//   - Authed update download: agent OR user key required (ships the ACKed
//     contract: ?file= compat + ?os=&arch= latest-match, X-Trace-SHA256
//     always, X-Trace-Signature when TRACE_UPDATE_SIGNING_KEY set).
//   - Authed vuln feed (agent-self or PermAgentRead user).
//   - Admin org/user/provision-token CRUD behind PermAdmin, envelope
//     responses, cursor pagination on lists, audit on mutations.
//   - ServeHTTP: request-ID middleware, honest /readyz (DB+TSE+disk, 503 when
//     down), authed /metrics + dashboard/API gating hookup (dashboard pkg
//     takes the Auth gate via DashboardAuth), TLS-optional with plaintext warn.

func (h *SyncHandler) handleEDRUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET required")
		return
	}
	agentVer := r.URL.Query().Get("version")
	if agentVer == "" {
		writeAPIError(w, r, http.StatusBadRequest, "version required")
		return
	}
	if h.updateDir == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	entries, err := os.ReadDir(h.updateDir)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var latestVer, latestFile string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if ver, ok := extractAgentVersion(name); ok {
			if latestVer == "" || compareSemver(ver, latestVer) > 0 {
				latestVer = ver
				latestFile = name
			}
		}
	}
	if latestVer == "" || compareSemver(latestVer, agentVer) <= 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	binPath := filepath.Join(h.updateDir, latestFile)
	data, err := os.ReadFile(binPath)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sha := sha256.Sum256(data)
	downloadURL := "/api/v1/edr/update/download?file=" + urlQueryEscape(latestFile)
	writeData(w, r, http.StatusOK, map[string]any{
		"version":      latestVer,
		"download_url": downloadURL,
		"sha256":       hex.EncodeToString(sha[:]),
		"signature":    signUpdateSHA(sha[:]),
		"required":     false,
	})
}

// compareSemver compares dotted numeric versions ("1.2.3" > "1.2.10" is
// false). Non-numeric suffixes compare lexically. Returns -1/0/+1.
func compareSemver(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var sa, sb string
		if i < len(pa) {
			sa = pa[i]
		}
		if i < len(pb) {
			sb = pb[i]
		}
		na, ea := strconv.Atoi(strings.TrimRight(sa, "abcdefghijklmnopqrstuvwxyz-+"))
		nb, eb := strconv.Atoi(strings.TrimRight(sb, "abcdefghijklmnopqrstuvwxyz-+"))
		if ea == nil && eb == nil {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "%20"), "+", "%2B")
}

// resolveUpdateAsset picks the update file: explicit ?file= (compat, contained)
// or latest match for ?os=&arch= (server-selected, no client path).
func (h *SyncHandler) resolveUpdateAsset(r *http.Request) (string, error) {
	if h.updateDir == "" {
		return "", errNoUpdateDir
	}
	if f := r.URL.Query().Get("file"); f != "" {
		if strings.Contains(f, "/") || strings.Contains(f, "\\") || f == "." || f == ".." {
			return "", errBadAsset
		}
		return f, nil
	}
	wantOS := strings.ToLower(r.URL.Query().Get("os"))
	wantArch := strings.ToLower(r.URL.Query().Get("arch"))
	entries, err := os.ReadDir(h.updateDir)
	if err != nil {
		return "", errNoUpdateDir
	}
	var bestVer, bestFile string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ver, ok := extractAgentVersion(name)
		if !ok {
			continue
		}
		ln := strings.ToLower(name)
		if wantOS != "" && !strings.Contains(ln, wantOS) {
			continue
		}
		if wantArch != "" && !strings.Contains(ln, wantArch) {
			continue
		}
		if bestVer == "" || compareSemver(ver, bestVer) > 0 {
			bestVer, bestFile = ver, name
		}
	}
	if bestFile == "" {
		return "", errNoAsset
	}
	return bestFile, nil
}

var (
	errNoUpdateDir = errString("no update directory configured")
	errBadAsset    = errString("invalid asset")
	errNoAsset     = errString("no matching update asset")
)

type errString string

func (e errString) Error() string { return string(e) }

func (h *SyncHandler) handleEDRUpdateDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET required")
		return
	}
	fileName, err := h.resolveUpdateAsset(r)
	if err != nil {
		switch err {
		case errNoUpdateDir:
			writeAPIError(w, r, http.StatusNotFound, err.Error())
		case errBadAsset:
			writeAPIError(w, r, http.StatusForbidden, err.Error())
		default:
			writeAPIError(w, r, http.StatusNotFound, err.Error())
		}
		return
	}
	cleanBase := filepath.Clean(h.updateDir)
	binPath := filepath.Join(cleanBase, filepath.Clean(fileName))
	rel, err := filepath.Rel(cleanBase, binPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		writeAPIError(w, r, http.StatusForbidden, "invalid path")
		return
	}
	data, err := os.ReadFile(binPath)
	if err != nil {
		writeAPIError(w, r, http.StatusNotFound, "asset not found")
		return
	}
	sha := sha256.Sum256(data)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Trace-SHA256", hex.EncodeToString(sha[:]))
	if sig := signUpdateSHA(sha[:]); sig != "" {
		w.Header().Set("X-Trace-Signature", sig)
	}
	auditWrite(h.audit, r.Context(), auditActor(r), "update.downloaded", "update", fileName, "")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// signUpdateSHA returns base64(ed25519(sha)) over the published
// (version, sha256) binding when TRACE_UPDATE_SIGNING_KEY is set, else ""
// (SHA-only + warn, never refusal, when unkeyed). Served both as
// "signature" in the check JSON (agent trust root) and as
// X-Trace-Signature on downloads (installer path); the agent updater
// refuses unsigned-when-keyed per its fail-closed policy.
func signUpdateSHA(sha []byte) string {
	return updateSignatureFor(sha)
}

var builtinCVEFeed = []map[string]any{
	{"cve_id": "CVE-2024-3094", "package": "liblzma*", "cvss": 10, "severity": "critical", "description": "liblzma/xz backdoor — SSHD remote code execution"},
	{"cve_id": "CVE-2024-6387", "package": "openssh*", "cvss": 9.8, "severity": "critical", "description": "OpenSSH regreSSHion — remote code execution"},
	{"cve_id": "CVE-2024-2961", "package": "glibc", "cvss": 9.1, "severity": "critical", "description": "glibc iconv() out-of-bounds write"},
	{"cve_id": "CVE-2024-38477", "package": "httpd*", "cvss": 9.1, "severity": "critical", "description": "Apache HTTPd mod_proxy CRLF injection"},
	{"cve_id": "CVE-2024-38077", "package": "openssl*", "cvss": 8.6, "severity": "high", "description": "OpenSSL SSL_free() use-after-free"},
	{"cve_id": "CVE-2024-47575", "package": "openssl*", "cvss": 7.5, "severity": "high", "description": "OpenSSL certificate validation bypass"},
	{"cve_id": "CVE-2024-24790", "package": "golang", "cvss": 7.5, "severity": "high", "description": "Go net/netip IPv6 zone parsing DoS"},
	{"cve_id": "CVE-2024-27316", "package": "httpd*", "cvss": 8.1, "severity": "high", "description": "Apache HTTPd HTTP/2 CONTINUATION flood DoS"},
	{"cve_id": "CVE-2024-34102", "package": "nginx", "cvss": 7.5, "severity": "high", "description": "nginx MP4 module memory corruption"},
	{"cve_id": "CVE-2024-27309", "package": "apache2*", "cvss": 7.5, "severity": "high", "description": "Apache Kafka Connect JNDI injection"},
	{"cve_id": "CVE-2024-3247", "package": "nodejs*", "cvss": 7.5, "severity": "high", "description": "Node.js HTTP/2 CONTINUATION flood DoS"},
	{"cve_id": "CVE-2024-3499", "package": "python3*", "cvss": 8.1, "severity": "high", "description": "Python ipaddress hostname validation"},
	{"cve_id": "CVE-2024-4333", "package": "systemd", "cvss": 7.8, "severity": "high", "description": "systemd-resolved out-of-bounds read"},
	{"cve_id": "CVE-2024-2222", "package": "linux-image*", "cvss": 7.0, "severity": "high", "description": "Linux kernel netfilter use-after-free"},
	{"cve_id": "CVE-2024-35196", "package": "git", "cvss": 7.8, "severity": "high", "description": "Git clone path traversal via symlink"},
	{"cve_id": "CVE-2024-2511", "package": "libcurl*", "cvss": 5.3, "severity": "medium", "description": "curl OCSP stapling bypass"},
	{"cve_id": "CVE-2024-24989", "package": "nginx", "cvss": 6.5, "severity": "medium", "description": "nginx HTTP/2 memory disclosure"},
	{"cve_id": "CVE-2024-3148", "package": "redis*", "cvss": 5.5, "severity": "medium", "description": "Redis Lua script stack overflow"},
}

func (h *SyncHandler) handleEDRVulnFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeData(w, r, http.StatusOK, map[string]any{"cves": builtinCVEFeed})
}

func (h *SyncHandler) handleEDRConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		agentID := ctxAgentID(r)
		if agentID == "" {
			writeAPIError(w, r, http.StatusUnauthorized, "agent auth required")
			return
		}
		if h.configStore == nil {
			writeData(w, r, http.StatusOK, map[string]any{})
			return
		}
		writeData(w, r, http.StatusOK, h.configStore.Get())
	case http.MethodPut:
		// Fleet-wide config is admin-only (any-agent PUT was a trust hole).
		role := RoleFromContext(r.Context())
		if !HasPermission(role, PermAdmin) {
			writeAPIError(w, r, http.StatusForbidden, "admin permission required")
			return
		}
		if h.configStore == nil {
			writeAPIError(w, r, http.StatusNotFound, "config store not available")
			return
		}
		var cfg AgentRemoteConfig
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "invalid json")
			return
		}
		if err := h.configStore.Set(cfg); err != nil {
			slog.Warn("config save failed", "err", err)
			writeAPIError(w, r, http.StatusInternalServerError, "save failed")
			return
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "agent-config.updated", "config", "agent_defaults", "")
		writeData(w, r, http.StatusOK, map[string]string{"status": "saved"})
	default:
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET or PUT required")
	}
}

func extractAgentVersion(name string) (string, bool) {
	n := name
	if strings.HasSuffix(n, ".exe") {
		n = strings.TrimSuffix(n, ".exe")
	}
	const prefix = "trace-agent-v"
	if !strings.HasPrefix(n, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(n, prefix)
	// Version is the leading dotted-numeric run; trailing "-os-arch" stays in
	// the filename for ?os=&arch= matching.
	end := 0
	for end < len(rest) && (rest[end] >= '0' && rest[end] <= '9' || rest[end] == '.') {
		end++
	}
	ver := strings.Trim(strings.Trim(rest[:end], "."), " ")
	if ver == "" {
		return "", false
	}
	return ver, true
}

// ── Admin: orgs / users / provision tokens ──

func (h *SyncHandler) handleOrgs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Name string `json:"name"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
			writeAPIError(w, r, http.StatusBadRequest, "name required")
			return
		}
		if len(req.Name) > 128 {
			writeAPIError(w, r, http.StatusBadRequest, "name too long")
			return
		}
		id, err := h.manager.CreateOrg(r.Context(), strings.TrimSpace(req.Name))
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "create failed")
			return
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "org.created", "org", id, "name="+req.Name)
		writeData(w, r, http.StatusOK, map[string]string{"id": id, "name": req.Name})
		return
	}
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET or POST required")
		return
	}
	limit := parseLimit(r)
	offset := parseCursor(r)
	rows, err := h.manager.db.QueryContext(r.Context(),
		`SELECT id, name, created_at FROM server_orgs ORDER BY name LIMIT ? OFFSET ?`, limit+1, offset)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()
	type org struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var orgs []org
	for rows.Next() {
		var o org
		var createdAt string
		if err := rows.Scan(&o.ID, &o.Name, &createdAt); err != nil {
			continue
		}
		orgs = append(orgs, o)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	next := ""
	if len(orgs) > limit {
		orgs = orgs[:limit]
		next = encodeCursor(offset + limit)
	}
	if orgs == nil {
		orgs = []org{}
	}
	writeData(w, r, http.StatusOK, map[string]any{"orgs": orgs, "next_cursor": next})
}

func (h *SyncHandler) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Email  string `json:"email"`
			Role   string `json:"role"`
			OrgID  string `json:"org_id,omitempty"`
			APIKey string `json:"api_key"`
			Scope  string `json:"scope,omitempty"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Email) == "" || req.Role == "" {
			writeAPIError(w, r, http.StatusBadRequest, "email and role required")
			return
		}
		if !validRole(req.Role) {
			writeAPIError(w, r, http.StatusBadRequest, "unknown role")
			return
		}
		if len(req.Email) > 256 || !strings.Contains(req.Email, "@") {
			writeAPIError(w, r, http.StatusBadRequest, "invalid email")
			return
		}
		apiKey := req.APIKey
		generated := ""
		if apiKey == "" {
			raw := make([]byte, 24)
			if _, err := rand.Read(raw); err != nil {
				writeAPIError(w, r, http.StatusInternalServerError, "mint key failed")
				return
			}
			apiKey = hex.EncodeToString(raw)
			generated = apiKey
		}
		_ = generated
		id, err := h.manager.CreateUser(r.Context(), strings.TrimSpace(req.Email), apiKey, req.Role, req.OrgID)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "create failed")
			return
		}
		if req.Scope != "" && req.Scope != string(ScopeFull) && req.Scope != string(ScopeReadOnly) {
			writeAPIError(w, r, http.StatusBadRequest, "unknown scope")
			return
		}
		if req.Scope != "" {
			_, _ = h.manager.db.ExecContext(r.Context(),
				`UPDATE server_users SET scope = ? WHERE id = ?`, req.Scope, id)
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "user.created", "user", id,
			"email="+req.Email+" role="+req.Role+" org="+req.OrgID)
		// The raw key is returned once here; it is never logged or stored.
		writeData(w, r, http.StatusOK, map[string]string{
			"id": id, "api_key": apiKey, "role": req.Role, "org_id": req.OrgID,
		})
		return
	}
	if r.Method != http.MethodGet {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET or POST required")
		return
	}
	limit := parseLimit(r)
	offset := parseCursor(r)
	rows, err := h.manager.db.QueryContext(r.Context(),
		`SELECT id, email, role, COALESCE(org_id, ''), COALESCE(scope, 'full') FROM server_users ORDER BY email LIMIT ? OFFSET ?`,
		limit+1, offset)
	if err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	defer rows.Close()
	type user struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Role  string `json:"role"`
		OrgID string `json:"org_id"`
		Scope string `json:"scope"`
	}
	var users []user
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.OrgID, &u.Scope); err != nil {
			continue
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, r, http.StatusInternalServerError, "query error")
		return
	}
	next := ""
	if len(users) > limit {
		users = users[:limit]
		next = encodeCursor(offset + limit)
	}
	if users == nil {
		users = []user{}
	}
	writeData(w, r, http.StatusOK, map[string]any{"users": users, "next_cursor": next})
}

func (h *SyncHandler) handleAdminUserByEmail(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users/")
	email = strings.TrimSuffix(email, "/rotate-key")
	if strings.HasSuffix(r.URL.Path, "/rotate-key") && r.Method == http.MethodPost {
		if !strings.Contains(email, "@") || len(email) > 256 {
			writeAPIError(w, r, http.StatusBadRequest, "invalid email")
			return
		}
		newKey, err := h.manager.RotateAPIKey(r.Context(), email)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "rotate failed")
			return
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "user.key_rotated", "user", email, "")
		writeData(w, r, http.StatusOK, map[string]string{"email": email, "api_key": newKey})
		return
	}
	writeAPIError(w, r, http.StatusNotFound, "not found")
}

// handleProvisionTokens: POST {org_id,label,ttl_hours} mints; GET lists;
// DELETE ?prefix= revokes. All behind PermAdmin.
func (h *SyncHandler) handleProvisionTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			OrgID    string `json:"org_id"`
			Label    string `json:"label"`
			TTLHours int    `json:"ttl_hours"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OrgID == "" {
			writeAPIError(w, r, http.StatusBadRequest, "org_id required")
			return
		}
		ttl := time.Duration(req.TTLHours) * time.Hour
		tok, err := h.manager.MintProvisionToken(r.Context(), req.OrgID, req.Label, ttl)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "mint failed")
			return
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "provision.minted", "provision", shortID(tok), "org="+req.OrgID)
		// Raw token returned once; never logged.
		writeData(w, r, http.StatusOK, map[string]string{"provision_token": tok, "org_id": req.OrgID})
	case http.MethodGet:
		orgID := r.URL.Query().Get("org_id")
		toks, err := h.manager.ListProvisionTokens(r.Context(), orgID)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "query error")
			return
		}
		writeData(w, r, http.StatusOK, map[string]any{"tokens": toks})
	case http.MethodDelete:
		prefix := r.URL.Query().Get("prefix")
		if !validResourceID(prefix) {
			writeAPIError(w, r, http.StatusBadRequest, "prefix required")
			return
		}
		if err := h.manager.RevokeProvisionToken(r.Context(), prefix); err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "revoke failed")
			return
		}
		auditWrite(h.audit, r.Context(), auditActor(r), "provision.revoked", "provision", prefix, "")
		writeData(w, r, http.StatusOK, map[string]string{"status": "revoked"})
	default:
		writeAPIError(w, r, http.StatusMethodNotAllowed, "GET, POST or DELETE required")
	}
}

func (h *SyncHandler) handleComplianceSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, r, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Hostname   string  `json:"hostname"`
		Framework  string  `json:"framework"`
		Score      float64 `json:"score"`
		Total      int     `json:"total"`
		Passed     int     `json:"passed"`
		Failed     int     `json:"failed"`
		NotCovered int     `json:"not_covered"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Hostname) == "" || len(req.Hostname) > 256 {
		writeAPIError(w, r, http.StatusBadRequest, "hostname required")
		return
	}
	if err := h.manager.RecordComplianceSnapshot(r.Context(), "", req.Hostname, req.Framework,
		req.Score, req.Total, req.Passed, req.Failed, req.NotCovered, nil); err != nil {
		writeAPIError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	auditWrite(h.audit, r.Context(), auditActor(r), "compliance.snapshot", "compliance",
		req.Hostname+"/"+req.Framework, "")
	writeData(w, r, http.StatusOK, map[string]string{"status": "recorded"})
}

type ServeOptions struct {
	ListenAddr string
	CertFile   string
	KeyFile    string
	LogDir     string
	DataDir    string
	UpdateDir  string
	DB         *sql.DB
	TSEWriter  EventWriter
	TSEHealthy func() bool
	DiskFree   func() (freeBytes, totalBytes uint64)
}

func ServeHTTP(opts ServeOptions, mgr *ServerManager, dashboard DashboardDataProvider) (*http.Server, error) {
	mux := http.NewServeMux()
	sm := newServerMetrics()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		type check struct {
			name string
			ok   bool
		}
		var checks []check
		dbOK := false
		if opts.DB != nil {
			if err := opts.DB.Ping(); err == nil {
				dbOK = true
			}
		} else if mgr != nil && mgr.db != nil {
			if err := mgr.db.DB.Ping(); err == nil {
				dbOK = true
			}
		}
		tseOK := true
		if opts.TSEHealthy != nil {
			tseOK = opts.TSEHealthy()
		}
		checks = append(checks, check{"tse", tseOK})
		diskOK := true
		if opts.DiskFree != nil {
			if free, total := opts.DiskFree(); total > 0 {
				if float64(free)/float64(total) < 0.05 {
					diskOK = false
				}
			}
		}
		checks = append(checks, check{"disk", diskOK})
		ready := dbOK && tseOK && diskOK
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ready {
			var failed []string
			for _, c := range checks {
				if !c.ok {
					failed = append(failed, c.name)
				}
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready: " + strings.Join(failed, ",")))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// Metrics bind behind auth (or localhost + explicit flag handled by
		// the caller); same-port open metrics plane is closed.
		auth := newAuth(mgr, sm)
		if _, ok := auth.authenticateUser(r); !ok {
			if _, ok2 := auth.authenticateAgent(r); !ok2 {
				writeAPIError(w, r, http.StatusUnauthorized, "unauthorized")
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sm.prometheusText()))
		_, _ = w.Write([]byte(metrics.PrometheusText()))
	})

	syncH := NewSyncHandler(mgr).WithLogDir(opts.LogDir).WithMetrics(sm)
	if opts.DataDir != "" {
		syncH.configStore = newRemoteConfigStore(opts.DataDir)
	}
	if opts.UpdateDir != "" {
		syncH.updateDir = opts.UpdateDir
	}
	if opts.TSEWriter != nil {
		syncH.tseWriter = opts.TSEWriter
	}
	syncH.RegisterRoutes(mux)

	dashboardHandler := NewDashboardHandler(dashboard)
	dashboardHandler.RegisterRoutes(mux, newAuth(mgr, sm))

	var handler http.Handler = mux
	handler = RequestIDMiddleware(handler)
	handler = metricsMiddleware(sm, handler)
	if opts.CertFile == "" || opts.KeyFile == "" {
		slog.Warn("serving plaintext HTTP: set TLS cert/key for hostile networks")
	}

	srv := &http.Server{
		Addr:              opts.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		if opts.CertFile != "" && opts.KeyFile != "" {
			slog.Info("HTTPS API + dashboard", "addr", opts.ListenAddr)
			if err := srv.ListenAndServeTLS(opts.CertFile, opts.KeyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTPS error", "err", err)
			}
		} else {
			slog.Info("HTTP API + dashboard", "addr", opts.ListenAddr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP error", "err", err)
			}
		}
	}()

	return srv, nil
}

// metricsMiddleware counts http_requests_total{route,code}.
func metricsMiddleware(sm *serverMetrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		sm.incRequest(routeLabel(r.URL.Path), rec.code)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// routeLabel collapses dynamic path segments for metric cardinality.
func routeLabel(p string) string {
	switch {
	case strings.HasPrefix(p, "/api/v1/edr/agents/"):
		return "/api/v1/edr/agents/:id"
	case strings.HasPrefix(p, "/api/v1/investigations/"):
		return "/api/v1/investigations/:id"
	case strings.HasPrefix(p, "/api/v1/timeline/"):
		return "/api/v1/timeline/:id"
	case strings.HasPrefix(p, "/api/v1/admin/users/"):
		return "/api/v1/admin/users/:email"
	case strings.HasPrefix(p, "/investigations/"):
		return "/investigations/:id"
	default:
		return p
	}
}

func serverBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
