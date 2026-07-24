package cold

import (
	"context"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

func TestReaderPool_New(t *testing.T) {
	p := NewReaderPool(0)
	if p == nil {
		t.Fatal("expected non-nil pool")
	}
	if cap(p.sem) != DefaultMaxConcurrent {
		t.Errorf("expected sem size %d, got %d", DefaultMaxConcurrent, cap(p.sem))
	}
}

func TestReaderPool_CustomLimit(t *testing.T) {
	p := NewReaderPool(8)
	if cap(p.sem) != 8 {
		t.Errorf("expected sem size 8, got %d", cap(p.sem))
	}
}

func TestReaderPool_Name(t *testing.T) {
	p := NewReaderPool(1)
	if p.Name() == "" {
		t.Error("expected non-empty name")
	}
}

func TestReaderPool_DelegatesToParquetReader(t *testing.T) {
	p := NewReaderPool(1)

	// Missing file should produce warning (delegation test)
	result, err := p.QueryFiles(context.Background(), []storage.FileInfo{
		{Path: "/nonexistent/file.parquet"},
	}, storage.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 0 {
		t.Errorf("expected 0 events, got %d", len(result.Events))
	}
	if len(result.Warnings) == 0 {
		t.Error("expected warning for missing file")
	}
}

func TestReaderPool_SemaphoreBlocksAtCapacity(t *testing.T) {
	p := NewReaderPool(2)

	// Fill the semaphore
	p.sem <- struct{}{}
	p.sem <- struct{}{}

	// Verify it's full
	if len(p.sem) != 2 {
		t.Fatalf("expected semaphore at capacity 2, got %d", len(p.sem))
	}

	// Drain
	<-p.sem
	<-p.sem
}
