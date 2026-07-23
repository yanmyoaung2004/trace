package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFIMBaselineAddsNewFile(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan *Event, 100)
	cfg := &FIMConfig{
		WatchPaths:   []string{dir},
		MaxSizeMB:    1,
		ScanInterval: 1 * time.Hour,
		DataDir:      dir,
	}
	f := NewFIMMonitor(ch, cfg)
	if err := f.Start(nil); err != nil {
		t.Fatal(err)
	}
	defer f.Stop()

	// Create a file
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	// Run scan
	f.scan()

	// Check event emitted
	select {
	case evt := <-ch:
		if evt.Annotations["change_type"] != "fim_added" {
			t.Errorf("expected fim_added, got %s", evt.Annotations["change_type"])
		}
		if evt.File == nil || evt.File.Path != path {
			t.Errorf("expected path %s, got %v", path, evt.File)
		}
	default:
		t.Fatal("expected event, got none")
	}
}

func TestFIMDetectsHashChange(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan *Event, 100)
	cfg := &FIMConfig{
		WatchPaths:   []string{dir},
		MaxSizeMB:    1,
		ScanInterval: 1 * time.Hour,
		DataDir:      dir,
	}
	f := NewFIMMonitor(ch, cfg)
	if err := f.Start(nil); err != nil {
		t.Fatal(err)
	}
	defer f.Stop()

	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("original"), 0644)
	f.scan()
	// Drain event
	<-ch

	// Modify file
	os.WriteFile(path, []byte("modified"), 0644)
	f.scan()

	select {
	case evt := <-ch:
		if evt.Annotations["change_type"] != "fim_modified" {
			t.Errorf("expected fim_modified, got %s", evt.Annotations["change_type"])
		}
	default:
		t.Fatal("expected modification event")
	}
}

func TestFIMDetectsDelete(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan *Event, 100)
	cfg := &FIMConfig{
		WatchPaths:   []string{dir},
		MaxSizeMB:    1,
		ScanInterval: 1 * time.Hour,
		DataDir:      dir,
	}
	f := NewFIMMonitor(ch, cfg)
	if err := f.Start(nil); err != nil {
		t.Fatal(err)
	}
	defer f.Stop()

	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello"), 0644)
	f.scan()
	<-ch // drain add event

	os.Remove(path)
	f.scan()

	select {
	case evt := <-ch:
		if evt.Annotations["change_type"] != "fim_deleted" {
			t.Errorf("expected fim_deleted, got %s", evt.Annotations["change_type"])
		}
	default:
		t.Fatal("expected deletion event")
	}
}

func TestFIMNoDuplicateDeleteEvents(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan *Event, 100)
	cfg := &FIMConfig{
		WatchPaths:   []string{dir},
		MaxSizeMB:    1,
		ScanInterval: 1 * time.Hour,
		DataDir:      dir,
	}
	f := NewFIMMonitor(ch, cfg)
	if err := f.Start(nil); err != nil {
		t.Fatal(err)
	}
	defer f.Stop()

	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello"), 0644)
	f.scan()
	<-ch // drain add
	os.Remove(path)

	// First scan after delete
	f.scan()
	<-ch // drain delete

	// Second scan should NOT emit another delete
	f.scan()
	select {
	case <-ch:
		t.Fatal("expected no duplicate delete event")
	default:
	}
}

func TestFIMSkipLargeFile(t *testing.T) {
	dir := t.TempDir()
	watchDir := filepath.Join(dir, "watch")
	os.MkdirAll(watchDir, 0755)
	ch := make(chan *Event, 100)
	cfg := &FIMConfig{
		WatchPaths:   []string{watchDir},
		MaxSizeMB:    1,
		ScanInterval: 1 * time.Hour,
		DataDir:      dir,
	}
	f := NewFIMMonitor(ch, cfg)

	// Create 10 files: 9 small (under 1MB) and 1 large (10MB)
	smallPath := filepath.Join(watchDir, "small.txt")
	os.WriteFile(smallPath, []byte("small file"), 0644)
	largePath := filepath.Join(watchDir, "large.bin")
	largeData := make([]byte, 10*1024*1024)
	os.WriteFile(largePath, largeData, 0644)

	f.Start(nil)
	defer f.Stop()

	time.Sleep(200 * time.Millisecond)

	// Should only have events for the small file
	seenSmall, seenLarge := false, false
	for {
		select {
		case evt := <-ch:
			if strings.HasSuffix(evt.File.Path, "small.txt") {
				seenSmall = true
			}
			if strings.HasSuffix(evt.File.Path, "large.bin") {
				seenLarge = true
			}
		default:
			if !seenSmall {
				t.Fatal("expected event for small file")
			}
			if seenLarge {
				t.Fatal("large file should have been skipped")
			}
			return
		}
	}
}

func TestFIMStopRace(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan *Event, 100)
	cfg := &FIMConfig{
		WatchPaths:   []string{dir},
		MaxSizeMB:    1,
		ScanInterval: 1 * time.Hour,
		DataDir:      dir,
	}
	f := NewFIMMonitor(ch, cfg)
	f.Start(nil)

	// Race: scan and stop concurrently
	go f.scan()
	go f.scan()
	f.Stop()
}
