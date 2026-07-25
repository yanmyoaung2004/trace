package storage

import "fmt"

// ErrDiskFull is returned when the storage volume has exceeded the maximum
// allowed disk usage ratio (DiskFullRatio = 95%).
var ErrDiskFull = fmt.Errorf("disk full: cannot accept more events")

// StoragePathFunc is set by the caller to provide the storage path for disk checks.
var StoragePathFunc func() string

const (
	// DiskWarnRatio is the usage ratio above which a warning is logged.
	DiskWarnRatio = 0.85
	// DiskFullRatio is the usage ratio above which writes are rejected.
	DiskFullRatio = 0.95
)

// IsDiskFull returns true if the disk usage exceeds the full threshold.
func IsDiskFull(usage *DiskUsage) bool {
	return usage.UsedRatio >= DiskFullRatio
}

// IsDiskWarning returns true if the disk usage exceeds the warning threshold.
func IsDiskWarning(usage *DiskUsage) bool {
	return usage.UsedRatio >= DiskWarnRatio
}
