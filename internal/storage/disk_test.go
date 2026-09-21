package storage

import (
	"errors"
	"testing"
)

func TestDiskThresholds(t *testing.T) {
	if !IsDiskWarning(&DiskUsage{UsedRatio: 0.86}) {
		t.Error("expected warn at 86%")
	}
	if IsDiskWarning(&DiskUsage{UsedRatio: 0.84}) {
		t.Error("expected no warn at 84%")
	}
	if !IsDiskFull(&DiskUsage{UsedRatio: 0.95}) {
		t.Error("expected full at 95%")
	}
	if IsDiskFull(&DiskUsage{UsedRatio: 0.949}) {
		t.Error("expected no full at 94.9%")
	}
}

func TestGetDiskUsageHook(t *testing.T) {
	prev := DiskCheckFunc
	defer func() { DiskCheckFunc = prev }()
	DiskCheckFunc = func(path string) (*DiskUsage, error) {
		return &DiskUsage{TotalBytes: 100, FreeBytes: 5, UsedRatio: 0.95}, nil
	}
	du, err := GetDiskUsage("unused")
	if err != nil {
		t.Fatal(err)
	}
	if !IsDiskFull(du) {
		t.Error("expected hooked usage to report full")
	}
}

func TestGetDiskUsageHookErr(t *testing.T) {
	prev := DiskCheckFunc
	defer func() { DiskCheckFunc = prev }()
	sentinel := errors.New("nope")
	DiskCheckFunc = func(path string) (*DiskUsage, error) { return nil, sentinel }
	if _, err := GetDiskUsage("unused"); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestLogDiskWarnThrottle(t *testing.T) {
	lastDiskWarnUnix.Store(0)
	if !LogDiskWarn(&DiskUsage{UsedRatio: 0.9}) {
		t.Fatal("expected first warn to log")
	}
	if LogDiskWarn(&DiskUsage{UsedRatio: 0.9}) {
		t.Error("expected second warn within a minute to be throttled")
	}
	if LogDiskWarn(nil) {
		t.Error("expected nil usage to not log")
	}
	if LogDiskWarn(&DiskUsage{UsedRatio: 0.5}) {
		t.Error("expected below-threshold usage to not log")
	}
}
