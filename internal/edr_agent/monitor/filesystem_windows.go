//go:build windows

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
	"golang.org/x/sys/windows"
)

type RDCFileMonitor struct {
	eventCh    chan<- *Event
	handles    []windows.Handle
	events     []windows.Overlapped
	paths      []string
	buffers    [][]byte
	exclude    []string
	mu         sync.Mutex
	done       chan struct{}
	pollFallback bool
	started    bool
}

func NewRDCFileMonitor(eventCh chan<- *Event, watchPaths, exclude []string) *RDCFileMonitor {
	return &RDCFileMonitor{
		eventCh: eventCh,
		exclude: exclude,
		done:    make(chan struct{}),
	}
}

func (m *RDCFileMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}

	paths := []string{
		os.Getenv("TEMP"),
		os.Getenv("LOCALAPPDATA") + "\\Temp",
		os.Getenv("WINDIR") + "\\Temp",
		os.Getenv("PROGRAMDATA"),
	}

	addif := func(p string) {
		if p != "" && !strings.HasPrefix(p, "\\") {
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
	}
	for _, p := range paths {
		addif(p)
	}

	unique := map[string]bool{}
	for _, p := range paths {
		if !unique[p] && p != "" {
			unique[p] = true
			if err := m.watchDir(p); err != nil {
				log.Printf("[file-mon] RDCW watch %s: %v", p, err)
			}
		}
	}

	if len(m.handles) == 0 {
		return m.fallback(ctx)
	}

	m.started = true
	log.Printf("[file-mon] ReadDirectoryChangesW active (%d watches)", len(m.handles))
	return nil
}

func (m *RDCFileMonitor) watchDir(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	h, err := windows.CreateFile(ptr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		return err
	}

	buf := make([]byte, 64*1024)
	var ov windows.Overlapped
	ov.HEvent, _ = windows.CreateEvent(nil, 0, 0, nil)

	m.handles = append(m.handles, h)
	m.paths = append(m.paths, path)
	m.events = append(m.events, ov)
	m.buffers = append(m.buffers, buf)

	go m.readLoop(len(m.handles) - 1)

	return nil
}

func (m *RDCFileMonitor) readLoop(idx int) {
	h := m.handles[idx]
	path := m.paths[idx]
	buf := m.buffers[idx]
	ov := &m.events[idx]

	for {
		select {
		case <-m.done:
			windows.CloseHandle(h)
			windows.CloseHandle(ov.HEvent)
			return
		default:
		}

		if err := windows.ReadDirectoryChanges(h, &buf[0], uint32(len(buf)), true,
			windows.FILE_NOTIFY_CHANGE_FILE_NAME|
				windows.FILE_NOTIFY_CHANGE_DIR_NAME|
				windows.FILE_NOTIFY_CHANGE_LAST_WRITE|
				windows.FILE_NOTIFY_CHANGE_CREATION,
			nil, ov, 0); err != nil {
			time.Sleep(time.Second)
			continue
		}

		if _, err := windows.WaitForSingleObject(ov.HEvent, windows.INFINITE); err != nil {
			continue
		}

		var transferred uint32
		windows.GetOverlappedResult(h, ov, &transferred, false)

		m.processNotifications(buf[:transferred], path)
	}
}

type fileNotifyInfo struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        [1]uint16
}

func (m *RDCFileMonitor) processNotifications(data []byte, basePath string) {
	offset := 0
	for offset < len(data) {
		if offset+12 > len(data) {
			break
		}
		info := (*fileNotifyInfo)(unsafe.Pointer(&data[offset]))
		if info.FileNameLength == 0 {
			break
		}

		nameLen := int(info.FileNameLength) / 2
		if nameLen > 512 {
			break
		}
		name16 := make([]uint16, nameLen)
		src := (*[512]uint16)(unsafe.Pointer(&data[offset+12]))[:nameLen]
		copy(name16, src)
		name := windows.UTF16ToString(name16)

		fullPath := filepath.Join(basePath, name)
		m.emitRDCEvent(info.Action, fullPath)

		if info.NextEntryOffset == 0 {
			break
		}
		offset += int(info.NextEntryOffset)
	}
}

func (m *RDCFileMonitor) emitRDCEvent(action uint32, path string) {
	var etype EventType
	sev := SeverityInfo

	switch action {
	case windows.FILE_ACTION_ADDED:
		etype = EventFileCreate
		if isSuspiciousPath(path) {
			sev = SeverityWarning
		}
	case windows.FILE_ACTION_MODIFIED:
		etype = EventFileModify
	case windows.FILE_ACTION_REMOVED:
		etype = EventFileDelete
	case windows.FILE_ACTION_RENAMED_OLD_NAME:
		etype = EventFileDelete
	case windows.FILE_ACTION_RENAMED_NEW_NAME:
		etype = EventFileCreate
		if isSuspiciousPath(path) {
			sev = SeverityWarning
		}
	default:
		return
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      etype,
		Severity:  sev,
		File:      &FileInfo{Path: path},
	}
	if sev >= SeverityWarning {
		evt.Annotations = map[string]string{"source": "rdcw", "reason": "suspicious_path"}
	}

	select {
	case m.eventCh <- evt:
	default:
	}
}

func (m *RDCFileMonitor) fallback(ctx context.Context) error {
	log.Printf("[file-mon] ReadDirectoryChangesW unavailable, falling back to polling")
	fm := NewFileMonitor(m.eventCh, []string{os.Getenv("TEMP")}, m.exclude)
	go fm.pollingLoop(ctx)
	m.pollFallback = true
	m.started = true
	return nil
}
