package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type FileMonitor struct {
	eventCh     chan<- *Event
	watchPaths  []string
	exclude     []string
	interval    time.Duration
	done        chan struct{}
	snapshots   map[string]fileState
	mu          sync.Mutex
	maxSize     int64
}

type fileState struct {
	Size    int64
	ModTime time.Time
	Mode    os.FileMode
}

func NewFileMonitor(eventCh chan<- *Event, watchPaths, exclude []string) *FileMonitor {
	return &FileMonitor{
		eventCh:    eventCh,
		watchPaths: watchPaths,
		exclude:    exclude,
		interval:   15 * time.Second,
		done:       make(chan struct{}),
		snapshots:  make(map[string]fileState),
		maxSize:    100 * 1024 * 1024,
	}
}

func (fm *FileMonitor) Start(ctx context.Context) error {
	go fm.pollingLoop(ctx)
	return nil
}

func (fm *FileMonitor) Stop() {
	close(fm.done)
}

func (fm *FileMonitor) pollingLoop(ctx context.Context) {
	tick := time.NewTicker(fm.interval)
	defer tick.Stop()

	for {
		select {
		case <-fm.done:
			return
		case <-tick.C:
			fm.scan()
		}
	}
}

func (fm *FileMonitor) scan() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	current := make(map[string]fileState)

	for _, root := range fm.watchPaths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if fm.isExcluded(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if info.Size() > fm.maxSize {
				return nil
			}
			if fm.isExcluded(path) {
				return nil
			}

			state := fileState{
				Size:    info.Size(),
				ModTime: info.ModTime(),
				Mode:    info.Mode(),
			}
			current[path] = state

			prev, exists := fm.snapshots[path]
			if !exists {
				fm.emitFileEvent(EventFileCreate, path, info)
			} else if prev.ModTime != state.ModTime || prev.Size != state.Size {
				fm.emitFileEvent(EventFileModify, path, info)
			}

			return nil
		})
		if err != nil {
			log.Printf("[file-monitor] walk error %s: %v", root, err)
		}
	}

	for path := range fm.snapshots {
		if _, exists := current[path]; !exists {
			fm.emitFileEvent(EventFileDelete, path, nil)
		}
	}

	fm.snapshots = current
}

func (fm *FileMonitor) isExcluded(path string) bool {
	lower := strings.ToLower(path)
	for _, ex := range fm.exclude {
		if strings.Contains(lower, strings.ToLower(ex)) {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) emitFileEvent(etype EventType, path string, info os.FileInfo) {
	sev := SeverityInfo
	if isSuspiciousPath(path) {
		sev = SeverityWarning
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      etype,
		Severity:  sev,
		File: &FileInfo{
			Path: path,
		},
	}

	if info != nil {
		evt.File.Size = info.Size()
		evt.File.Mode = info.Mode().String()
		evt.File.Hash = fm.computeHash(path)
	}

	if sev >= SeverityWarning {
		evt.Annotations = map[string]string{"reason": "suspicious_path"}
	}

	select {
	case fm.eventCh <- evt:
	default:
	}
}

func (fm *FileMonitor) computeHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.CopyN(h, f, 1*1024*1024); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func isSuspiciousPath(path string) bool {
	lower := strings.ToLower(path)
	suspicious := []string{
		"temp", "tmp", "appdata\\local\\temp", "\\temp\\", "\\tmp\\",
		"downloads", "desktop\\", "startup\\", "\\appdata\\roaming\\",
		"\\users\\public\\", "recycle.bin", "system32\\tasks\\",
		"programdata\\", "autostart",
	}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func init() {
	if runtime.GOOS == "linux" {
		detectInotify()
	}
}

func detectInotify() {
	if _, err := os.Stat("/proc/sys/fs/inotify"); err == nil {
		log.Printf("[file-monitor] inotify available")
	}
}
