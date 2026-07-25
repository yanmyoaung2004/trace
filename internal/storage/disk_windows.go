//go:build windows

package storage

import "golang.org/x/sys/windows"

// DiskUsage holds filesystem capacity and free space.
type DiskUsage struct {
	TotalBytes uint64
	FreeBytes  uint64
	UsedRatio  float64
}

// CheckDisk returns disk usage for the given path (Windows).
func CheckDisk(path string) (*DiskUsage, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &free, &total, &totalFree); err != nil {
		return nil, err
	}
	usage := &DiskUsage{TotalBytes: total, FreeBytes: free}
	if total > 0 {
		usage.UsedRatio = float64(total-free) / float64(total)
	}
	return usage, nil
}
