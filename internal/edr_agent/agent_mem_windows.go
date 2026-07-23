package edr_agent

import (
	"fmt"
	"os/exec"
	"strings"
)

func getWindowsTotalRAM() int64 {
	out, err := exec.Command("powershell", "-Command",
		"[math]::Round((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize/1024)").Output()
	if err != nil {
		return 0
	}
	var total int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &total)
	return total
}

func getWindowsProcessMemoryMB() int64 {
	out, err := exec.Command("powershell", "-Command",
		"[math]::Round((Get-Process -Id $pid).WorkingSet64/1MB)").Output()
	if err != nil {
		return 0
	}
	var ws int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &ws)
	return ws
}

func getWindowsCPUName() string {
	out, err := exec.Command("powershell", "-Command",
		"(Get-CimInstance Win32_Processor).Name").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
