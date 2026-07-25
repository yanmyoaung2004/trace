package storage

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
