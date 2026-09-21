package sift

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWarmBuiltin_FromSeedStore verifies WarmBuiltin loads the hash subset of
// intel/seed-iocs.json (single store) and never consults a second builtin map:
// a seeded Mimikatz hash resolves malicious with the seed-file confidence,
// while a non-hash seed entry (domain) is not warmed into the hash cache.
func TestWarmBuiltin_FromSeedStore(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "intel", "seed-iocs.json")); err != nil {
		t.Skip("seed-iocs.json not reachable from package dir")
	}
	db := testDB(t)
	hc := NewHashCache(db)

	hc.WarmBuiltin(t.Context())

	mimikatz, err := hc.Get(t.Context(), "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
	if err != nil {
		t.Fatal(err)
	}
	if mimikatz == nil {
		t.Fatal("expected Mimikatz hash warmed from seed store")
	}
	if mimikatz.Reputation != "malicious" || mimikatz.Source != "builtin" {
		t.Errorf("got %+v, want malicious/builtin", mimikatz)
	}
	if mimikatz.Confidence != 0.95 {
		t.Errorf("confidence = %v, want 0.95 (seed-iocs.json value)", mimikatz.Confidence)
	}

	if got, _ := hc.Get(t.Context(), "evil.com"); got != nil {
		t.Errorf("domain seed entry must not warm the hash cache, got %+v", got)
	}
}

// TestWarmBuiltin_ExactOnly verifies hash lookups are exact: a truncated
// digest or a hash with surrounding whitespace/prefix does not match.
func TestWarmBuiltin_ExactOnly(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "..", "intel", "seed-iocs.json")); err != nil {
		t.Skip("seed-iocs.json not reachable from package dir")
	}
	db := testDB(t)
	hc := NewHashCache(db)
	hc.WarmBuiltin(t.Context())

	if got, _ := hc.Get(t.Context(), "275a021bbfb6489e54d471899f7db9d"); got != nil {
		t.Errorf("truncated digest must not match, got %+v", got)
	}
}
