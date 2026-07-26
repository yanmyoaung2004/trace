package hunt

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yanmyoaung2004/trace/internal/db"
)

func TestSchedulerStartStop(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	mgr := NewManager(d)
	s := NewScheduler(mgr, nil, nil, nil, nil, nil)
	s.tick = time.Hour // won't fire during test

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		s.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // let it start
	cancel()

	select {
	case <-done:
		// OK — scheduler stopped cleanly
	case <-time.After(time.Second):
		t.Fatal("scheduler didn't stop within 1s after cancel")
	}
}

func TestSchedulerCheckNoPanic(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	mgr := NewManager(d)
	s := NewScheduler(mgr, nil, nil, nil, nil, nil)

	// check() should not panic when there are no due hunts
	s.check(context.Background())
}
