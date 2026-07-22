//go:build linux

package monitor

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	fanClassNotify    = 0
	fanOpen           = 0x00000020
	fanAccess         = 0x00000001
	fanModify         = 0x00000002
	fanCloseWrite     = 0x00000008
	fanCloseNoWrite   = 0x00000010
	fanReportFID      = 0x00000200
	fanEpochOnClose   = 0x00000040
	fanMarkAdd        = 0x00000001
	fanMarkMount      = 0x00000010
	fanMarkFilesystem = 0x00000100
	fanNoai           = 0x00001000
	fanOpenExec       = 0x00001000
)

type FanotifyMonitor struct {
	eventCh    chan<- *Event
	fd         int
	pidFd      int
	done       chan struct{}
	mu         sync.Mutex
	started    bool
}

func NewFanotifyMonitor(eventCh chan<- *Event) *FanotifyMonitor {
	return &FanotifyMonitor{
		eventCh: eventCh,
		done:    make(chan struct{}),
	}
}

func (m *FanotifyMonitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}

	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_DFID_NAME|fanNoai), uint(os.O_RDONLY))
	if err != nil {
		log.Printf("[fanotify] init: %v (requires CAP_SYS_ADMIN)", err)
		return err
	}

	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT,
		unix.FAN_OPEN|unix.FAN_ACCESS|unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE,
		unix.AT_FDCWD, "/"); err != nil {
		log.Printf("[fanotify] mark: %v", err)
		unix.Close(fd)
		return err
	}

	m.fd = fd
	m.started = true

	go m.readLoop()
	log.Printf("[fanotify] active (monitoring all mounts)")
	return nil
}

func (m *FanotifyMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return
	}
	m.started = false
	close(m.done)
	unix.Close(m.fd)
}

func (m *FanotifyMonitor) readLoop() {
	buf := make([]byte, 4096)
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
			log.Printf("[fanotify] read: %v", err)
			return
		}

		m.processEvents(buf[:n])
	}
}

func (m *FanotifyMonitor) processEvents(data []byte) {
	// Parse fanotify event metadata
	// Each event is struct fanotify_event_metadata:
	//   event_len (u32), vers (u8), reserved (u8),
	//   metadata_len (u16), mask (u64), fd (s32),
	//   pid (u32)
	const metaHdrLen = 24

	for offset := 0; offset+metaHdrLen <= len(data); {
		eventLen := int(data[3])<<24 | int(data[2])<<16 | int(data[1])<<8 | int(data[0])
		mask := int64(data[11])<<56 | int64(data[10])<<48 | int64(data[9])<<40 | int64(data[8])<<32 |
			int64(data[7])<<24 | int64(data[6])<<16 | int64(data[5])<<8 | int64(data[4])
		evFd := int(int32(data[19])<<24 | int32(data[18])<<16 | int32(data[17])<<8 | int32(data[16]))
		pid := int(int32(data[23])<<24 | int32(data[22])<<16 | int32(data[21])<<8 | int32(data[20]))

		if evFd >= 0 && mask > 0 {
			// Resolve fd to path
			path := resolveFD(evFd)
			unix.Close(evFd)

			if path != "" && !isIgnoredPath(path) {
				m.emitEvent(mask, path, pid)
			}
		}

		if eventLen <= 0 {
			break
		}
		offset += eventLen
	}
}

func resolveFD(fd int) string {
	dest, err := os.Readlink(filepath.Join("/proc/self/fd", itoa(fd)))
	if err != nil {
		return ""
	}
	return dest
}

func isIgnoredPath(path string) bool {
	ignored := []string{
		"/proc/", "/sys/", "/dev/", "/run/",
		"/var/lib/docker", "/var/lib/containerd",
		"/snap/", "/var/snap",
	}
	for _, p := range ignored {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (m *FanotifyMonitor) emitEvent(mask int64, path string, pid int) {
	var etype EventType
	sev := SeverityInfo

	switch {
	case mask&unix.FAN_OPEN != 0:
		etype = EventFileCreate
		if isSuspiciousPath(path) {
			sev = SeverityWarning
		}
	case mask&unix.FAN_ACCESS != 0:
		etype = EventNetListen
	case mask&unix.FAN_MODIFY != 0:
		etype = EventFileModify
	case mask&unix.FAN_CLOSE_WRITE != 0:
		etype = EventFileModify
	default:
		return
	}

	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      etype,
		Severity:  sev,
		File:      &FileInfo{Path: path},
		Process:   &ProcessInfo{PID: pid},
	}
	if sev >= SeverityWarning {
		evt.Annotations = map[string]string{"source": "fanotify", "reason": "file_open"}
	}

	select {
	case m.eventCh <- evt:
	default:
	}
}


