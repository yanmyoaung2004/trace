//go:build !windows

package storage

import "syscall"

// DiskUsage holds filesystem capacity and free space.
type DiskUsage struct {
	TotalBytes uint64
	FreeBytes  uint64
	UsedRatio  float64
}

// CheckDisk returns disk usage for the given path (Unix).
func CheckDisk(path string) (*DiskUsage, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return nil, err
	}
	total := fs.Blocks * uint64(fs.Bsize)
	free := fs.Bavail * uint64(fs.Bsize)
	usage := &DiskUsage{TotalBytes: total, FreeBytes: free}
	if total > 0 {
		usage.UsedRatio = float64(total-free) / float64(total)
	}
	return usage, nil
}
