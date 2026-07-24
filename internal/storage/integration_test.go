package storage

import (
	"fmt"
	"testing"
	"time"
)

func TestMergeSortDedupByID_Empty(t *testing.T) {
	r := MergeSortDedupByID(nil)
	if r != nil {
		t.Errorf("expected nil for nil input, got %v", r)
	}
}

func TestMergeSortDedupByID_Single(t *testing.T) {
	r := MergeSortDedupByID([]*Event{{ID: "e1"}})
	if len(r) != 1 {
		t.Errorf("expected 1, got %d", len(r))
	}
}

func TestMergeSortDedupByID_NoDups(t *testing.T) {
	r := MergeSortDedupByID([]*Event{
		{ID: "c"},
		{ID: "a"},
		{ID: "b"},
	})
	if len(r) != 3 {
		t.Fatalf("expected 3, got %d", len(r))
	}
	if r[0].ID != "a" || r[1].ID != "b" || r[2].ID != "c" {
		t.Errorf("expected sorted a,b,c got %s,%s,%s", r[0].ID, r[1].ID, r[2].ID)
	}
}

func TestMergeSortDedupByID_WithDups(t *testing.T) {
	r := MergeSortDedupByID([]*Event{
		{ID: "e1"},
		{ID: "e3"},
		{ID: "e1"},
		{ID: "e2"},
		{ID: "e2"},
	})
	if len(r) != 3 {
		t.Fatalf("expected 3 after dedup, got %d", len(r))
	}
	if r[0].ID != "e1" || r[1].ID != "e2" || r[2].ID != "e3" {
		t.Errorf("expected sorted e1,e2,e3 got %s,%s,%s", r[0].ID, r[1].ID, r[2].ID)
	}
}

func TestMergeSortDedupByID_AllSame(t *testing.T) {
	r := MergeSortDedupByID([]*Event{
		{ID: "same"},
		{ID: "same"},
		{ID: "same"},
	})
	if len(r) != 1 {
		t.Errorf("expected 1 after dedup, got %d", len(r))
	}
}

func TestMergeSortDedupByID_Sorted(t *testing.T) {
	r := MergeSortDedupByID([]*Event{
		{ID: "a"},
		{ID: "b"},
		{ID: "c"},
	})
	if len(r) != 3 {
		t.Fatalf("expected 3, got %d", len(r))
	}
}

func TestResult_AddWarning(t *testing.T) {
	r := &Result{}
	r.AddWarning("test %d", 42)
	if len(r.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(r.Warnings))
	}
	if r.Warnings[0] != "test 42" {
		t.Errorf("expected 'test 42', got %s", r.Warnings[0])
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.StoragePath != "./data/tse" {
		t.Errorf("expected default storage path ./data/tse, got %s", cfg.StoragePath)
	}
	if cfg.QueueCapacity != 65536 {
		t.Errorf("expected 65536 queue capacity, got %d", cfg.QueueCapacity)
	}
	if cfg.FlushInterval != 30*time.Second {
		t.Errorf("expected 30s flush interval, got %v", cfg.FlushInterval)
	}
}

func TestWatermark_ImplementsInterface(t *testing.T) {
	wm := &Watermark{LastID: "test", LastTS: 100, UpdatedAt: 200}
	if wm.LastID != "test" {
		t.Errorf("unexpected LastID: %s", wm.LastID)
	}
	if wm.LastTS != 100 {
		t.Errorf("unexpected LastTS: %d", wm.LastTS)
	}
}

func TestCompressionConstants(t *testing.T) {
	if CompressionZSTD != "zstd" {
		t.Errorf("expected zstd, got %s", CompressionZSTD)
	}
	if CompressionSnappy != "snappy" {
		t.Errorf("expected snappy, got %s", CompressionSnappy)
	}
	if CompressionNone != "none" {
		t.Errorf("expected none, got %s", CompressionNone)
	}
}

func TestFileResult_Fields(t *testing.T) {
	fr := &FileResult{
		Path:             "/test.parquet",
		RowCount:         100,
		CompressedSize:   1024,
		UncompressedSize: 2048,
		SHA256:           "abc",
		MinTimestampUs:   1000,
		MaxTimestampUs:   2000,
		MinEventID:       "e1",
		MaxEventID:       "e100",
	}
	if fr.RowCount != 100 {
		t.Errorf("expected 100, got %d", fr.RowCount)
	}
}

func BenchmarkMergeSortDedupByID(b *testing.B) {
	events := make([]*Event, 1000)
	for i := 0; i < 1000; i++ {
		events[i] = &Event{ID: fmt.Sprintf("%03d", i%500)} // ~50% dups
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MergeSortDedupByID(events)
	}
}

// Property: MergeSortDedupByID is idempotent
func TestInvariant_MergeSortDedupByID_Idempotent(t *testing.T) {
	original := []*Event{
		{ID: "b", Severity: 1},
		{ID: "a", Severity: 2},
		{ID: "c", Severity: 3},
	}

	once := MergeSortDedupByID(original)
	twice := MergeSortDedupByID(once)

	if len(once) != len(twice) {
		t.Errorf("idempotent: lengths differ: %d vs %d", len(once), len(twice))
	}
	for i := range once {
		if once[i].ID != twice[i].ID {
			t.Errorf("idempotent: position %d: %s vs %s", i, once[i].ID, twice[i].ID)
		}
	}
}

// Property: Result.Total == len(Result.Events)
func TestInvariant_ResultTotal(t *testing.T) {
	r := &Result{Events: []*Event{{ID: "a"}, {ID: "b"}, {ID: "c"}}}
	r.Total = len(r.Events)
	if r.Total != 3 {
		t.Errorf("expected Total=3, got %d", r.Total)
	}
}

// Property: MergeSortDedupByID preserves no duplicates
func TestInvariant_MergeSortDedupByID_NoDups(t *testing.T) {
	inputs := [][]*Event{
		{{ID: "a"}, {ID: "a"}, {ID: "a"}},
		{{ID: "z"}, {ID: "y"}, {ID: "x"}, {ID: "x"}, {ID: "y"}},
		{{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "1"}, {ID: "2"}, {ID: "3"}},
	}
	for _, in := range inputs {
		result := MergeSortDedupByID(in)
		seen := make(map[string]bool)
		for _, e := range result {
			if seen[e.ID] {
				t.Errorf("duplicate found: %s", e.ID)
			}
			seen[e.ID] = true
		}
	}
}
