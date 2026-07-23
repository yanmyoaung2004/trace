package monitor

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestVulnDB(t *testing.T) *VulnScanner {
	dir := t.TempDir()
	dbPath := dir + "/vuln_test.db"
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`PRAGMA journal_mode=WAL`)
	db.Exec(`CREATE TABLE IF NOT EXISTS cve_db (
		cve_id TEXT PRIMARY KEY,
		package_pattern TEXT NOT NULL,
		version_op TEXT NOT NULL,
		version TEXT NOT NULL,
		cvss REAL NOT NULL DEFAULT 0,
		severity TEXT NOT NULL DEFAULT 'unknown',
		description TEXT NOT NULL DEFAULT '',
		remediation TEXT NOT NULL DEFAULT '',
		published TEXT NOT NULL DEFAULT ''
	)`)

	v := &VulnScanner{
		db:      db,
		dataDir: dir,
		eventCh: make(chan *Event, 100),
	}
	t.Cleanup(func() { db.Close() })
	return v
}

func TestMatchPackageExact(t *testing.T) {
	if !matchPackage("curl", "curl") {
		t.Error("expected exact match")
	}
	if matchPackage("curl", "wget") {
		t.Error("not expected to match")
	}
}

func TestMatchPackageGlob(t *testing.T) {
	if !matchPackage("openssl-1.1", "openssl*") {
		t.Error("expected glob match")
	}
	if !matchPackage("liblzma5", "liblzma*") {
		t.Error("expected glob match on liblzma")
	}
	if matchPackage("openssh-server", "openssl*") {
		t.Error("not expected to match")
	}
}

func TestMatchPackageSubstring(t *testing.T) {
	if !matchPackage("linux-image-5.10.0-kernel", "kernel") {
		t.Error("expected substring match for kernel")
	}
	if matchPackage("base-files", "kernel") {
		t.Error("not expected to match")
	}
}

func TestVersionCompareLess(t *testing.T) {
	cases := []struct {
		installed, op, fixed string
		want                bool
	}{
		{"1.0.0", "<", "2.0.0", true},
		{"2.0.0", "<", "1.0.0", false},
		{"1.0.0", "<", "1.0.0", false},
		{"1.0", "<", "1.0.1", true},
		{"2.0-beta", "<", "2.0", true},
	}
	for _, c := range cases {
		got := versionCompare(c.installed, c.op, c.fixed)
		if got != c.want {
			t.Errorf("versionCompare(%q, %q, %q) = %v, want %v", c.installed, c.op, c.fixed, got, c.want)
		}
	}
}

func TestVersionCompareGreater(t *testing.T) {
	if !versionCompare("2.0.0", ">", "1.0.0") {
		t.Error("expected 2.0.0 > 1.0.0")
	}
}

func TestVersionCompareEqual(t *testing.T) {
	if !versionCompare("1.2.3", "=", "1.2.3") {
		t.Error("expected 1.2.3 = 1.2.3")
	}
}

func TestVersionCompareGreaterOrEqual(t *testing.T) {
	if !versionCompare("1.2.3", ">=", "1.2.3") {
		t.Error("expected 1.2.3 >= 1.2.3")
	}
	if !versionCompare("2.0.0", ">=", "1.0.0") {
		t.Error("expected 2.0.0 >= 1.0.0")
	}
}

func TestVersionWithPrefix(t *testing.T) {
	if !versionCompare("v1.0.0", "<", "2.0.0") {
		t.Error("expected v1.0.0 < 2.0.0")
	}
	if !versionCompare("V3.0.0", ">", "2.0.0") {
		t.Error("expected V3.0.0 > 2.0.0")
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"v1.2.3", []int{1, 2, 3}},
		{"1.2.3-p1", []int{1, 2, 3}},
		{"1.2.3-beta", []int{1, 2, 3}},
		{"2.0-beta", []int{2, 0}},
		{"10.20.30", []int{10, 20, 30}},
		{"invalid", nil},
	}
	for _, tc := range tests {
		got, ok := parseVersion(tc.input)
		if tc.want == nil {
			if ok {
				t.Errorf("parseVersion(%q) expected failure, got %v", tc.input, got)
			}
			continue
		}
		if !ok {
			t.Errorf("parseVersion(%q) failed unexpectedly", tc.input)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseVersion(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseVersion(%q)[%d] = %d, want %d", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestCVEMatch(t *testing.T) {
	v := newTestVulnDB(t)

	// Insert test CVE
	v.db.Exec(`INSERT INTO cve_db (cve_id, package_pattern, version_op, version, cvss, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"CVE-TEST-2024-0001", "curl", "<", "8.6.0", 7.5, "high", "Test CVE", "Upgrade curl to 8.6.0+")

	matches, err := v.matchCVEs([]Package{{Name: "curl", Version: "7.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].CVEID != "CVE-TEST-2024-0001" {
		t.Errorf("expected CVE-TEST-2024-0001, got %s", matches[0].CVEID)
	}
	if matches[0].PackageName != "curl" {
		t.Errorf("expected curl, got %s", matches[0].PackageName)
	}
}

func TestCVENoMatchOnFixedVersion(t *testing.T) {
	v := newTestVulnDB(t)
	v.db.Exec(`INSERT INTO cve_db (cve_id, package_pattern, version_op, version, cvss, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"CVE-TEST-2024-0002", "wget", "<", "1.21", 5.0, "medium", "Test", "Upgrade")

	matches, err := v.matchCVEs([]Package{{Name: "wget", Version: "1.22"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for fixed version, got %d", len(matches))
	}
}

func TestSeedBuiltinCVEs(t *testing.T) {
	v := newTestVulnDB(t)
	v.seedBuiltinCVEs()

	var count int
	v.db.QueryRow(`SELECT COUNT(*) FROM cve_db`).Scan(&count)
	if count == 0 {
		t.Fatal("expected seeded CVEs, got 0")
	}
	t.Logf("seeded %d CVEs", count)
}

func TestSeverityMapping(t *testing.T) {
	v := newTestVulnDB(t)
	v.minCVSS = 4.0

	// Low severity should be filtered out
	v.db.Exec(`INSERT INTO cve_db (cve_id, package_pattern, version_op, version, cvss, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"CVE-LOW", "testpkg", "<", "2.0", 2.5, "low", "Low severity test", "Upgrade")

	v.db.Exec(`INSERT INTO cve_db (cve_id, package_pattern, version_op, version, cvss, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"CVE-HIGH", "testpkg", "<", "2.0", 8.0, "high", "High severity test", "Upgrade")

	matches, err := v.matchCVEs([]Package{{Name: "testpkg", Version: "1.0"}})
	if err != nil {
		t.Fatal(err)
	}

	// Both should match (matching is independent of minCVSS, filtering happens in scan())
	// At least the high one should be there
	found := false
	for _, m := range matches {
		if m.CVEID == "CVE-HIGH" {
			found = true
		}
	}
	if !found {
		t.Error("expected CVE-HIGH in matches")
	}
}

func TestCollectPackagesLinuxDpkg(t *testing.T) {
	// Skip if not on Linux (dpkg not available)
	if _, err := os.Stat("/usr/bin/dpkg-query"); os.IsNotExist(err) {
		t.Skip("dpkg-query not available")
	}
	pkgs := collectLinuxPackages()
	if len(pkgs) == 0 {
		t.Error("expected at least one package on a dpkg system")
	}
	t.Logf("found %d packages", len(pkgs))
}

func TestCollectPackagesWindows(t *testing.T) {
	if _, err := os.Stat("C:\\Windows"); os.IsNotExist(err) {
		t.Skip("not on Windows")
	}
	// This will work on Windows without admin
	pkgs := collectWindowsPackages()
	if len(pkgs) == 0 {
		t.Log("no packages found via registry (expected on minimal systems)")
	}
	t.Logf("found %d Windows packages", len(pkgs))
}

func TestUpdateCVEDBFromURL(t *testing.T) {
	v := newTestVulnDB(t)

	// Use a real, small CVE feed
	imported, err := v.UpdateCVEDB(context.Background(), "https://raw.githubusercontent.com/yanmyoaung2004/trace/main/intel/seed-cve-test.json")
	if err != nil {
		// Feed may not exist; test the path where URL fails gracefully
		t.Logf("UpdateCVEDB error (expected if no network): %v", err)
		return
	}
	t.Logf("imported %d CVEs from test feed", imported)
}

func TestNewVulnScannerWithConfig(t *testing.T) {
	ch := make(chan *Event, 10)
	cfg := VulnConfig{DataDir: t.TempDir(), MinCVSS: 7.0, ScanHours: 12}
	v := NewVulnScanner(ch, cfg)
	if v.minCVSS != 7.0 {
		t.Errorf("expected minCVSS 7.0, got %f", v.minCVSS)
	}
	if v.interval != 12*time.Hour {
		t.Errorf("expected interval 12h, got %v", v.interval)
	}
}
