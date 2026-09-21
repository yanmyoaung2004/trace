package asset

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// InventoryFile is the JSON shape for file-local asset inventory:
//
//	{"assets":[{"id":"web-01","hostname":"web-01","type":"host","criticality":8}],
//	 "vulns":[{"cve_id":"CVE-2024-0001","cvss":9.8,"severity":"critical","asset_id":"web-01"}]}
//
// File-local on purpose: server DB schema stays owned by the ServerTrust
// area (additive CREATE IF NOT EXISTS only, coordinated via hub).

// InventoryFile is the on-disk inventory document.
type InventoryFile struct {
	Assets []Asset `json:"assets"`
	Vulns  []Vuln  `json:"vulns"`
}

// DefaultInventoryPath returns ~/.trace/assets.json.
func DefaultInventoryPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trace", "assets.json")
}

// LoadInventory reads and parses an inventory file. Types are normalized;
// unknown type strings become TypeUnknown rather than failing the load.
func LoadInventory(path string) ([]Asset, []Vuln, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read inventory %s: %w (expect {\"assets\":[...],\"vulns\":[...]})", path, err)
	}
	var inv InventoryFile
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, nil, fmt.Errorf("parse inventory %s: %w", path, err)
	}
	for i := range inv.Assets {
		inv.Assets[i].Type = NormalizeType(string(inv.Assets[i].Type))
	}
	return inv.Assets, inv.Vulns, nil
}
