//go:build !windows

package edr_agent

func getWindowsTotalRAM() int64 { return 0 }

func getWindowsProcessMemoryMB() int64 { return 0 }

func getWindowsCPUName() string { return "" }
