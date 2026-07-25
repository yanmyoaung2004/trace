//go:build windows

package service

import (
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestServiceExecute_StartStop(t *testing.T) {
	var started, stopped atomic.Bool

	ts := &traceService{
		startFn: func() { started.Store(true) },
		stopFn:  func() { stopped.Store(true) },
	}

	requests := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status)

	go func() {
		// Send initial status read (test will read it)
		status := <-changes
		if status.State != svc.StartPending {
			t.Errorf("expected StartPending, got %v", status.State)
		}
		// Read running status
		status = <-changes
		if status.State != svc.Running {
			t.Errorf("expected Running, got %v", status.State)
		}
		if !started.Load() {
			t.Error("expected startFn to be called")
		}

		// Send stop command
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
		status = <-changes
		if status.State != svc.StopPending {
			t.Errorf("expected StopPending, got %v", status.State)
		}
		status = <-changes
		if status.State != svc.Stopped {
			t.Errorf("expected Stopped, got %v", status.State)
		}
		if !stopped.Load() {
			t.Error("expected stopFn to be called")
		}
		close(requests)
	}()

	ts.Execute(nil, requests, changes)
}

func TestServiceExecute_Interrogate(t *testing.T) {
	ts := &traceService{
		startFn: func() {},
		stopFn:  func() {},
	}

	requests := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status)

	go func() {
		<-changes // StartPending
		status := <-changes // Running
		// Interrogate returns current status
		requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: status}
		reply := <-changes
		if reply.State != svc.Running {
			t.Errorf("expected Running after interrogate, got %v", reply.State)
		}
		requests <- svc.ChangeRequest{Cmd: svc.Stop}
		<-changes // StopPending
		<-changes // Stopped
		close(requests)
	}()

	ts.Execute(nil, requests, changes)
}

func TestServiceExecute_Shutdown(t *testing.T) {
	var stopped bool
	ts := &traceService{
		startFn: func() {},
		stopFn:  func() { stopped = true },
	}

	requests := make(chan svc.ChangeRequest)
	changes := make(chan svc.Status, 10)

	go func() {
		<-changes // StartPending
		<-changes // Running
		requests <- svc.ChangeRequest{Cmd: svc.Shutdown}
		<-changes // StopPending
		<-changes // Stopped
		close(requests)
	}()

	ts.Execute(nil, requests, changes)
	if !stopped {
		t.Error("expected stopFn to be called on shutdown")
	}
}

func TestServiceRun_NotService(t *testing.T) {
	// On a non-service run, RunService should call startFn directly
	var started bool
	RunService(func() { started = true }, func() {})
	time.Sleep(50 * time.Millisecond)
	if !started {
		t.Error("expected startFn to be called when not running as service")
	}
}
