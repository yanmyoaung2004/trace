//go:build windows

package service

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "TraceEDRAgent"
const serviceDesc = "Trace EDR Endpoint Agent — Monitors endpoints and executes remote response actions."

func Install(exePath string) error {
	exe, err := filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: serviceName,
		Description: serviceDesc,
	}, "--service")
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}

	return nil
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	return nil
}

type traceService struct {
	stopFn func()
	mu     sync.Mutex
	stopped bool
}

func (ts *traceService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range requests {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			ts.mu.Lock()
			if ts.stopFn != nil {
				ts.stopFn()
			}
			ts.stopped = true
			ts.mu.Unlock()
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}

	return false, 0
}

func RunService(runFn func()) {
	ts := &traceService{}
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("[service] IsWindowsService check failed: %v (running as console)", err)
		runFn()
		return
	}
	if !isService {
		log.Printf("[service] not running as Windows service (console mode)")
		runFn()
		return
	}

	// Register the SCM event loop
	ts.stopFn = runFn
	elog, err := os.OpenFile(filepath.Join(os.TempDir(), "trace-agent-svc.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer elog.Close()
	}

	if err := svc.Run(serviceName, ts); err != nil {
		log.Printf("[service] svc.Run failed: %v", err)
		runFn()
	}
}

var _ = windows.GetCurrentProcess
