//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
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

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	return nil
}

func RunService(runFn func()) {
	runFn()
}

var _ = windows.GetCurrentProcess
var _ = os.DevNull
