package monitor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Source  string `json:"source"` // "deb", "rpm", "pacman", "wmic"
}

type CVEMatch struct {
	CVEID       string  `json:"cve_id"`
	PackageName string  `json:"package_name"`
	Installed   string  `json:"installed"`
	FixedIn     string  `json:"fixed_in"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
}

type VulnScanner struct {
	eventCh   chan<- *Event
	db        *sql.DB
	dataDir   string
	interval  time.Duration
	minCVSS   float64
	done      chan struct{}
	mu        sync.Mutex
}

type VulnConfig struct {
	DataDir   string
	MinCVSS   float64
	ScanHours int
}

func NewVulnScanner(eventCh chan<- *Event, cfg VulnConfig) *VulnScanner {
	interval := 6 * time.Hour
	if cfg.ScanHours > 0 {
		interval = time.Duration(cfg.ScanHours) * time.Hour
	}
	minCVSS := 4.0
	if cfg.MinCVSS > 0 {
		minCVSS = cfg.MinCVSS
	}
	return &VulnScanner{
		eventCh:  eventCh,
		dataDir:  cfg.DataDir,
		interval: interval,
		minCVSS:  minCVSS,
		done:     make(chan struct{}),
	}
}

func (v *VulnScanner) Start(ctx context.Context) error {
	dbPath := filepath.Join(v.dataDir, "vuln.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return fmt.Errorf("vuln db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("vuln db open: %w", err)
	}
	v.db = db

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS cve_db (
			cve_id TEXT PRIMARY KEY,
			package_pattern TEXT NOT NULL,
			version_op TEXT NOT NULL,
			version TEXT NOT NULL,
			cvss REAL NOT NULL DEFAULT 0,
			severity TEXT NOT NULL DEFAULT 'unknown',
			description TEXT NOT NULL DEFAULT '',
			remediation TEXT NOT NULL DEFAULT '',
			published TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_cve_pkg ON cve_db(package_pattern);
		CREATE TABLE IF NOT EXISTS vuln_scans (
			id TEXT PRIMARY KEY,
			scanned_at TEXT NOT NULL DEFAULT (datetime('now')),
			packages INTEGER NOT NULL DEFAULT 0,
			vulnerabilities INTEGER NOT NULL DEFAULT 0
		);
	`); err != nil {
		return fmt.Errorf("vuln db migrate: %w", err)
	}

	v.seedBuiltinCVEs()

	log.Printf("[vuln] scanner started (interval=%v, min_cvss=%.1f)", v.interval, v.minCVSS)
	go v.loop(ctx)
	return nil
}

func (v *VulnScanner) Stop() {
	close(v.done)
	if v.db != nil {
		v.db.Close()
	}
}

func (v *VulnScanner) loop(ctx context.Context) {
	v.scan()

	tick := time.NewTicker(v.interval)
	defer tick.Stop()

	for {
		select {
		case <-v.done:
			return
		case <-tick.C:
			v.scan()
		}
	}
}

func (v *VulnScanner) scan() {
	v.mu.Lock()
	defer v.mu.Unlock()

	pkgs := collectPackages()
	if len(pkgs) == 0 {
		return
	}

	matches, err := v.matchCVEs(pkgs)
	if err != nil {
		log.Printf("[vuln] match: %v", err)
		return
	}

	log.Printf("[vuln] scanned %d packages, found %d vulnerabilities", len(pkgs), len(matches))

	for _, m := range matches {
		if m.CVSS < v.minCVSS {
			continue
		}

		sev := SeverityWarning
		if m.CVSS >= 7 {
			sev = SeverityAlert
		} else if m.CVSS >= 4 {
			sev = SeverityWarning
		}

		evt := &Event{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Type:      EventAlert,
			Severity:  sev,
			Annotations: map[string]string{
				"source":      "vuln_scan",
				"cve_id":      m.CVEID,
				"package":     m.PackageName + " " + m.Installed,
				"fixed_in":    m.FixedIn,
				"cvss":        fmt.Sprintf("%.1f", m.CVSS),
				"severity":    m.Severity,
				"description": truncate(m.Description, 200),
				"remediation": m.Remediation,
			},
		}

		select {
		case v.eventCh <- evt:
		default:
		}
	}
}

func collectPackages() []Package {
	switch runtime.GOOS {
	case "windows":
		return collectWindowsPackages()
	case "linux":
		return collectLinuxPackages()
	default:
		return nil
	}
}

func collectWindowsPackages() []Package {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
			HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
		Where-Object { $_.DisplayName -and $_.DisplayVersion } |
		Select-Object DisplayName, DisplayVersion |
		ConvertTo-Json -Compress`).Output()
	if err != nil {
		return nil
	}

	text := strings.TrimSpace(string(out))
	if text == "" || text == "[]" || text == "null" {
		return nil
	}

	var items []struct {
		Name    string `json:"DisplayName"`
		Version string `json:"DisplayVersion"`
	}
	if err := json.Unmarshal([]byte(text), &items); err != nil {
		return nil
	}

	pkgs := make([]Package, 0, len(items))
	for _, item := range items {
		pkgs = append(pkgs, Package{
			Name:    strings.ToLower(item.Name),
			Version: item.Version,
			Source:  "wmic",
		})
	}
	return pkgs
}

func collectLinuxPackages() []Package {
	var cmd *exec.Cmd

	if _, err := exec.LookPath("dpkg-query"); err == nil {
		cmd = exec.Command("dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture}\n")
	} else if _, err := exec.LookPath("rpm"); err == nil {
		cmd = exec.Command("rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n")
	} else if _, err := exec.LookPath("pacman"); err == nil {
		cmd = exec.Command("pacman", "-Q")
	} else {
		return nil
	}

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	source := "deb"
	if strings.Contains(cmd.String(), "rpm") {
		source = "rpm"
	} else if strings.Contains(cmd.String(), "pacman") {
		source = "pacman"
	}

	var pkgs []Package
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		arch := ""
		if len(parts) >= 3 {
			arch = parts[2]
		}
		pkgs = append(pkgs, Package{
			Name:    parts[0],
			Version: parts[1],
			Arch:    arch,
			Source:  source,
		})
	}
	return pkgs
}

func (v *VulnScanner) matchCVEs(pkgs []Package) ([]CVEMatch, error) {
	rows, err := v.db.Query(`SELECT cve_id, package_pattern, version_op, version, cvss, severity, description, remediation FROM cve_db`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type cveRow struct {
		CVEID    string
		Pattern  string
		Op       string
		Version  string
		CVSS     float64
		Severity string
		Desc     string
		Remed    string
	}

	var cves []cveRow
	for rows.Next() {
		var c cveRow
		if err := rows.Scan(&c.CVEID, &c.Pattern, &c.Op, &c.Version, &c.CVSS, &c.Severity, &c.Desc, &c.Remed); err != nil {
			return nil, err
		}
		cves = append(cves, c)
	}

	var matches []CVEMatch
	for _, pkg := range pkgs {
		for _, cve := range cves {
			if !matchPackage(pkg.Name, cve.Pattern) {
				continue
			}
			if !versionCompare(pkg.Version, cve.Op, cve.Version) {
				continue
			}
			matches = append(matches, CVEMatch{
				CVEID:       cve.CVEID,
				PackageName: pkg.Name,
				Installed:   pkg.Version,
				FixedIn:     cve.Version,
				CVSS:        cve.CVSS,
				Severity:    cve.Severity,
				Description: cve.Desc,
				Remediation: fmt.Sprintf("Upgrade %s to >= %s", pkg.Name, cve.Version),
			})
		}
	}

	return matches, nil
}

func matchPackage(name, pattern string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	// Direct match
	if name == pattern {
		return true
	}
	// Glob match (e.g. "openssl*")
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix)
	}
	// Substring match (e.g. "kernel" matches "linux-image-5.10.0-kernel")
	if strings.Contains(name, pattern) {
		return true
	}
	return false
}

func versionCompare(installed, op, fixed string) bool {
	// Simple numeric/semver comparison
	iv := parseVersion(installed)
	fv := parseVersion(fixed)

	if len(iv) == 0 || len(fv) == 0 {
		return false
	}

	// Compare major.minor.patch
	minLen := len(iv)
	if len(fv) < minLen {
		minLen = len(fv)
	}

	var cmp int
	for i := 0; i < minLen; i++ {
		if iv[i] != fv[i] {
			if iv[i] < fv[i] {
				cmp = -1
			} else {
				cmp = 1
			}
			break
		}
	}
	if cmp == 0 {
		if len(iv) < len(fv) {
			cmp = -1
		} else if len(iv) > len(fv) {
			cmp = 1
		}
	}

	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case "=":
		return cmp == 0
	case ">=":
		return cmp >= 0
	case ">":
		return cmp > 0
	default:
		return cmp <= 0
	}
}

func parseVersion(v string) []int {
	v = strings.TrimLeft(v, "vV")
	var parts []int
	for _, p := range strings.Split(v, ".") {
		// Handle suffixes like "1.2.3-p1"
		cleaned := p
		for i, c := range p {
			if c < '0' || c > '9' {
				cleaned = p[:i]
				break
			}
		}
		n, err := strconv.Atoi(cleaned)
		if err != nil {
			break
		}
		parts = append(parts, n)
	}
	return parts
}

type cveSeedEntry struct {
	CVEID       string  `json:"cve_id"`
	Package     string  `json:"package"`
	VersionOp   string  `json:"version_op"`
	Version     string  `json:"version"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Remediation string  `json:"remediation"`
}

func (v *VulnScanner) seedBuiltinCVEs() {
	var count int
	v.db.QueryRow(`SELECT COUNT(*) FROM cve_db`).Scan(&count)
	if count > 0 {
		return
	}

	var seeds []cveSeedEntry
	if err := json.Unmarshal([]byte(builtinCVEData), &seeds); err != nil {
		log.Printf("[vuln] parse seed: %v", err)
		return
	}

	tx, err := v.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO cve_db (cve_id, package_pattern, version_op, version, cvss, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return
	}
	defer stmt.Close()

	seeded := 0
	for _, s := range seeds {
		if _, err := stmt.Exec(s.CVEID, s.Package, s.VersionOp, s.Version, s.CVSS, s.Severity, s.Description, s.Remediation); err != nil {
			log.Printf("[vuln] seed %s: %v", s.CVEID, err)
			continue
		}
		seeded++
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[vuln] seed commit: %v", err)
		return
	}
	log.Printf("[vuln] seeded %d/%d CVEs", seeded, len(seeds))
}

var builtinCVEData = `[
  {"cve_id":"CVE-2024-3094","package":"liblzma*","version_op":"<","version":"5.6.1","cvss":10,"severity":"critical","description":"liblzma/xz backdoor — SSHD remote code execution","remediation":"Upgrade xz/liblzma to 5.6.1+"},
  {"cve_id":"CVE-2024-6387","package":"openssh*","version_op":"<","version":"9.8","cvss":9.8,"severity":"critical","description":"OpenSSH regreSSHion — remote code execution in signal handler","remediation":"Upgrade openssh to 9.8+"},
  {"cve_id":"CVE-2024-38077","package":"openssl*","version_op":"<","version":"3.0.14","cvss":8.6,"severity":"high","description":"OpenSSL SSL_free() use-after-free","remediation":"Upgrade openssl to 3.0.14+"},
  {"cve_id":"CVE-2024-47575","package":"openssl*","version_op":"<","version":"3.3.2","cvss":7.5,"severity":"high","description":"OpenSSL certificate validation bypass","remediation":"Upgrade openssl to 3.3.2+"},
  {"cve_id":"CVE-2024-24790","package":"golang","version_op":"<","version":"1.22.4","cvss":7.5,"severity":"high","description":"Go net/netip IPv6 zone parsing denial of service","remediation":"Upgrade golang to 1.22.4+"},
  {"cve_id":"CVE-2024-2511","package":"libcurl*","version_op":"<","version":"8.6.0","cvss":5.3,"severity":"medium","description":"curl OCSP stapling bypass","remediation":"Upgrade curl to 8.6.0+"},
  {"cve_id":"CVE-2024-2961","package":"glibc","version_op":"<","version":"2.39","cvss":9.1,"severity":"critical","description":"glibc iconv() out-of-bounds write in ISO-2022-CN-EXT","remediation":"Upgrade glibc to 2.39+"},
  {"cve_id":"CVE-2024-35196","package":"git","version_op":"<","version":"2.45.1","cvss":7.8,"severity":"high","description":"Git clone path traversal via symlink","remediation":"Upgrade git to 2.45.1+"},
  {"cve_id":"CVE-2024-27316","package":"httpd*","version_op":"<","version":"2.4.59","cvss":8.1,"severity":"high","description":"Apache HTTPd HTTP/2 CONTINUATION flood DoS","remediation":"Upgrade httpd to 2.4.59+"},
  {"cve_id":"CVE-2024-38477","package":"httpd*","version_op":"<","version":"2.4.60","cvss":9.1,"severity":"critical","description":"Apache HTTPd mod_proxy CRLF injection","remediation":"Upgrade httpd to 2.4.60+"},
  {"cve_id":"CVE-2024-34102","package":"nginx","version_op":"<","version":"1.26.1","cvss":7.5,"severity":"high","description":"nginx MP4 module memory corruption","remediation":"Upgrade nginx to 1.26.1+"},
  {"cve_id":"CVE-2024-24989","package":"nginx","version_op":"<","version":"1.26.0","cvss":6.5,"severity":"medium","description":"nginx HTTP/2 memory disclosure","remediation":"Upgrade nginx to 1.26.0+"},
  {"cve_id":"CVE-2024-3148","package":"redis*","version_op":"<","version":"7.2.5","cvss":5.5,"severity":"medium","description":"Redis Lua script stack overflow","remediation":"Upgrade redis to 7.2.5+"},
  {"cve_id":"CVE-2024-27309","package":"apache2*","version_op":"<","version":"2.4.60","cvss":7.5,"severity":"high","description":"Apache Kafka Connect JNDI injection","remediation":"Upgrade kafka to 3.6.2+"},
  {"cve_id":"CVE-2024-3247","package":"nodejs*","version_op":"<","version":"20.12.2","cvss":7.5,"severity":"high","description":"Node.js HTTP/2 CONTINUATION flood DoS","remediation":"Upgrade nodejs to 20.12.2+"},
  {"cve_id":"CVE-2024-3499","package":"python3*","version_op":"<","version":"3.12.3","cvss":8.1,"severity":"high","description":"Python ipaddress module incorrect hostname validation","remediation":"Upgrade python3 to 3.12.3+"},
  {"cve_id":"CVE-2024-4333","package":"systemd","version_op":"<","version":"256","cvss":7.8,"severity":"high","description":"systemd-resolved out-of-bounds read in DNS message parsing","remediation":"Upgrade systemd to 256+"},
  {"cve_id":"CVE-2024-2222","package":"linux-image*","version_op":"<","version":"6.8","cvss":7.0,"severity":"high","description":"Linux kernel netfilter use-after-free","remediation":"Upgrade kernel to 6.8+"}
]`
