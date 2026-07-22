//go:build linux

package monitor

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type inotifyEvent struct {
	Wd     int32
	Mask   uint32
	Cookie uint32
	Len    uint32
	Name   [0]byte
}

type InotifyFileMonitor struct {
	eventCh    chan<- *Event
	fd         int
	watchMap   map[int]string
	mu         sync.Mutex
	exclude    []string
	done       chan struct{}
	started    bool
	pollFallback bool
}

func NewInotifyFileMonitor(eventCh chan<- *Event, watchPaths, exclude []string) *InotifyFileMonitor {
	return &InotifyFileMonitor{
		eventCh:  eventCh,
		watchMap: make(map[int]string),
		exclude:  exclude,
		done:     make(chan struct{}),
	}
}

func (m *InotifyFileMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}

	fd, err := unix.InotifyInit()
	if err != nil {
		log.Printf("[file-mon] inotify_init: %v", err)
		return m.fallback(ctx)
	}

	m.fd = fd
	m.started = true

	go m.watchLoop(ctx)
	log.Printf("[file-mon] inotify active (fd=%d)", fd)
	return nil
}

func (m *InotifyFileMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		close(m.done)
		if !m.pollFallback && m.fd > 0 {
			unix.Close(m.fd)
		}
	}
}

func (m *InotifyFileMonitor) fallback(ctx context.Context) error {
	log.Printf("[file-mon] falling back to polling")
	fm := NewFileMonitor(m.eventCh, []string{"/tmp", "/var/tmp"}, m.exclude)
	go fm.pollingLoop(ctx)
	m.pollFallback = true
	m.started = true
	return nil
}

func (m *InotifyFileMonitor) watchLoop(ctx context.Context) {
	m.addWatchRecursive("/tmp")
	m.addWatchRecursive("/var/tmp")
	m.addWatchRecursive("/etc")
	m.addWatchRecursive("/root")

	buf := make([]byte, 4096*10)

	for {
		select {
		case <-m.done:
			return
		default:
		}

		n, err := unix.Read(m.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			log.Printf("[file-mon] inotify read: %v", err)
			return
		}

		var offset int
		for offset+unix.SizeofInotifyEvent <= n {
			raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(raw.Len)
			name := ""
			if nameLen > 0 && offset+unix.SizeofInotifyEvent+nameLen <= n {
				nameBytes := make([]byte, nameLen)
				copy(nameBytes, buf[offset+unix.SizeofInotifyEvent:offset+unix.SizeofInotifyEvent+nameLen])
				name = strings.TrimRight(string(nameBytes), "\x00")
			}

			m.emitInotifyEvent(raw, name)
			offset += unix.SizeofInotifyEvent + nameLen
		}
	}
}

func (m *InotifyFileMonitor) addWatchRecursive(root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if m.isExcluded(path) {
				return filepath.SkipDir
			}
			wd, err := unix.InotifyAddWatch(m.fd, path, unix.IN_CREATE|unix.IN_MODIFY|unix.IN_DELETE|unix.IN_MOVED_TO|unix.IN_MOVED_FROM|unix.IN_ATTRIB)
			if err == nil {
				m.mu.Lock()
				m.watchMap[wd] = path
				m.mu.Unlock()
			}
		}
		return nil
	})
}

func (m *InotifyFileMonitor) isExcluded(path string) bool {
	lower := strings.ToLower(path)
	for _, ex := range m.exclude {
		if strings.Contains(lower, strings.ToLower(ex)) {
			return true
		}
	}
	return false
}

func (m *InotifyFileMonitor) emitInotifyEvent(raw *unix.InotifyEvent, name string) {
	m.mu.Lock()
	watchPath, ok := m.watchMap[int(raw.Wd)]
	m.mu.Unlock()
	if !ok {
		return
	}

	fullPath := filepath.Join(watchPath, name)
	if m.isExcluded(fullPath) {
		return
	}

	var etype EventType
	sev := SeverityInfo

	switch {
	case raw.Mask&unix.IN_CREATE != 0 || raw.Mask&unix.IN_MOVED_TO != 0:
		etype = EventFileCreate
		if isSuspiciousPath(fullPath) {
			sev = SeverityWarning
		}
		// If a directory was created, watch it too
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			wd, err := unix.InotifyAddWatch(m.fd, fullPath, unix.IN_CREATE|unix.IN_MODIFY|unix.IN_DELETE|unix.IN_MOVED_TO|unix.IN_MOVED_FROM|unix.IN_ATTRIB)
			if err == nil {
				m.mu.Lock()
				m.watchMap[wd] = fullPath
				m.mu.Unlock()
			}
		}
	case raw.Mask&unix.IN_MODIFY != 0:
		etype = EventFileModify
	case raw.Mask&unix.IN_DELETE != 0 || raw.Mask&unix.IN_MOVED_FROM != 0:
		etype = EventFileDelete
	case raw.Mask&unix.IN_ATTRIB != 0:
		etype = EventFileModify
	default:
		return
	}

	info, _ := os.Stat(fullPath)
	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      etype,
		Severity:  sev,
		File:      &FileInfo{Path: fullPath},
	}
	if info != nil {
		evt.File.Size = info.Size()
		evt.File.Mode = info.Mode().String()
	}
	if sev >= SeverityWarning {
		evt.Annotations = map[string]string{"source": "inotify", "reason": "suspicious_path"}
	}

	select {
	case m.eventCh <- evt:
	default:
	}
}
