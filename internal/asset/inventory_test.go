package asset

import (
	"os"
	"path/filepath"
	"testing"
)

func writeInventory(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "assets.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadInventory_RoundTrip(t *testing.T) {
	path := writeInventory(t, `{"assets":[
		{"id":"web-01","hostname":"web-01","ip":"10.0.0.11","os":"ubuntu-22.04","type":"host","criticality":8},
		{"id":"db-01","hostname":"db-01","type":"weird-type","criticality":10}
	],"vulns":[
		{"cve_id":"CVE-2024-0001","package_name":"openssl","installed":"1.1.1","fixed_in":"3.0.0","cvss":9.8,"severity":"critical","asset_id":"web-01"}
	]}`)
	assets, vulns, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(assets) != 2 || len(vulns) != 1 {
		t.Fatalf("got %d assets %d vulns, want 2+1", len(assets), len(vulns))
	}
	if assets[0].Type != TypeHost {
		t.Errorf("type = %q, want host", assets[0].Type)
	}
	if assets[1].Type != TypeUnknown {
		t.Errorf("unknown type should normalize, got %q", assets[1].Type)
	}
	if vulns[0].CVEID != "CVE-2024-0001" || vulns[0].AssetID != "web-01" {
		t.Errorf("vuln = %+v", vulns[0])
	}
	// End-to-end: inventory file feeds Join + Score for triage.
	scored := Join(assets, vulns)
	if len(scored) != 2 {
		t.Fatalf("Join = %d, want 2", len(scored))
	}
	if scored[0].ID != "web-01" {
		t.Errorf("top triage = %q, want web-01 (exposed + critical)", scored[0].ID)
	}
}

func TestLoadInventory_MissingFile(t *testing.T) {
	_, _, err := LoadInventory(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Error("expected error for missing inventory file")
	}
}

func TestLoadInventory_BadJSON(t *testing.T) {
	path := writeInventory(t, `{"assets": [oops]}`)
	if _, _, err := LoadInventory(path); err == nil {
		t.Error("expected error for malformed JSON")
	}
}
