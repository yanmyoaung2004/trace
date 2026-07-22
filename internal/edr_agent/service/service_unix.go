//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const serviceName = "trace-edr-agent"

func Install(exePath string) error {
	exe, err := filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	unit := fmt.Sprintf(`[Unit]
Description=Trace EDR Endpoint Agent
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10
LimitNOFILE=65536
Environment=TRACE_AGENT_SERVER=%s

[Install]
WantedBy=multi-user.target
`, exe, getEnvOrDefault("TRACE_AGENT_SERVER", "https://127.0.0.1:8080"))

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", serviceName).Run()
	exec.Command("systemctl", "start", serviceName).Run()

	fmt.Printf("Service installed: %s\n", unitPath)
	fmt.Printf("Run: systemctl status %s\n", serviceName)
	return nil
}

func Uninstall() error {
	exec.Command("systemctl", "stop", serviceName).Run()
	exec.Command("systemctl", "disable", serviceName).Run()
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", serviceName)
	os.Remove(unitPath)
	exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func RunService(runFn func()) {
	runFn()
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var _ = strings.TrimSpace
