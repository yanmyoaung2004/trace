package storage

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// ErrDiskFull is returned when the storage volume has exceeded the maximum
// allowed disk usage ratio (DiskFullRatio = 95%).
var ErrDiskFull = fmt.Errorf("disk full: cannot accept more events")

// StoragePathFunc is set by the caller to provide the storage path for disk checks.
var StoragePathFunc func() string

// DiskCheckFunc overrides CheckDisk when non-nil (tests simulate 85/95% usage
// without filling a real volume). Production leaves it nil to use the OS check.
var DiskCheckFunc func(path string) (*DiskUsage, error)

// GetDiskUsage returns disk usage for path via DiskCheckFunc hook or CheckDisk.
func GetDiskUsage(path string) (*DiskUsage, error) {
	if DiskCheckFunc != nil {
		return DiskCheckFunc(path)
	}
	return CheckDisk(path)
}

const (
	// DiskWarnRatio is the usage ratio above which a warning is logged.
	DiskWarnRatio = 0.85
	// DiskFullRatio is the usage ratio above which writes are rejected.
	DiskFullRatio = 0.95
)

// lastDiskWarnUnix throttles 85% warnings: the ingest path is hot and must
// not log on every batch while the disk sits above the warn threshold.
var lastDiskWarnUnix atomic.Int64

// LogDiskWarn logs a disk-usage warning at most once per minute. Callers
// invoke it when IsDiskWarning holds; it returns true when a line was logged.
func LogDiskWarn(usage *DiskUsage) bool {
	if usage == nil || !IsDiskWarning(usage) {
		return false
	}
	now := time.Now().Unix()
	for {
		last := lastDiskWarnUnix.Load()
		if now-last < 60 {
			return false
		}
		if lastDiskWarnUnix.CompareAndSwap(last, now) {
			log.Printf("[tse] WARNING: disk usage %.0f%% exceeds warn threshold %.0f%%",
				usage.UsedRatio*100, DiskWarnRatio*100)
			return true
		}
	}
}

// IsDiskFull returns true if the disk usage exceeds the full threshold.
func IsDiskFull(usage *DiskUsage) bool {
	return usage.UsedRatio >= DiskFullRatio
}

// IsDiskWarning returns true if the disk usage exceeds the warning threshold.
func IsDiskWarning(usage *DiskUsage) bool {
	return usage.UsedRatio >= DiskWarnRatio
}
