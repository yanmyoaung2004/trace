package archive

import (
	"testing"
)

// TestLookupBuiltin_ExactOnly pins the FP fix: partial strings must not match.
// "evil" must not resolve the "evil.com" builtin; short hash fragments must
// not resolve full digests.
func TestLookupBuiltin_ExactOnly(t *testing.T) {
	ic := NewIntelCache(nil)

	if got := ic.LookupBuiltin("evil"); len(got) != 0 {
		t.Errorf("substring 'evil' matched %v; want no match", got)
	}
	if got := ic.LookupBuiltin("275a021b"); len(got) != 0 {
		t.Errorf("hash fragment matched %v; want no match", got)
	}
	if got := ic.LookupBuiltin("eicar"); len(got) != 0 {
		t.Errorf("description fragment matched %v; want no match", got)
	}
	if got := ic.LookupBuiltin(""); len(got) != 0 {
		t.Errorf("empty query matched %v; want no match", got)
	}
}

// TestLookupBuiltin_ExactAndCIDR pins the two allowed match modes:
// normalized exact match (case/whitespace-insensitive) and CIDR containment.
func TestLookupBuiltin_ExactAndCIDR(t *testing.T) {
	ic := NewIntelCache(nil)

	if got := ic.LookupBuiltin("  EVIL.COM "); len(got) == 0 {
		t.Error("exact domain with different case/whitespace must match")
	} else if got[0].IOC != "evil.com" {
		t.Errorf("IOC = %q, want evil.com", got[0].IOC)
	}

	if got := ic.LookupBuiltin("E99A18C428CB38D5F260853678922E03"); len(got) == 0 {
		t.Error("exact hash with different case must match")
	}

	if got := ic.LookupBuiltin("185.220.101.99"); len(got) == 0 {
		t.Error("IP inside 185.220.101.0/24 must match via CIDR")
	} else if got[0].IOC != "185.220.101.0/24" {
		t.Errorf("IOC = %q, want 185.220.101.0/24", got[0].IOC)
	}

	if got := ic.LookupBuiltin("8.8.8.8"); len(got) != 0 {
		t.Errorf("unrelated IP matched %v; want no match", got)
	}
}
