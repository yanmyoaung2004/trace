//go:build linux

package monitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	cnIdxProc      = 0x1
	cnValProc      = 0x1
	procCnMcastListen = 0x1

	procEventFork = 0x00000002
	procEventExec = 0x00000004
)

type cnMsg struct {
	ID     struct {
		Idx uint32
		Val uint32
	}
	Seq    uint32
	Ack    uint32
	Length uint16
	Flags  uint16
}

type procEventHdr struct {
	_         [16]byte
	EventType uint32
	_         [4]byte
}

type forkEvent struct {
	ParentPID  uint32
	_          [4]byte
	ChildPID   uint32
	_          [4]byte
}

type LinuxProcMonitor struct {
	eventCh      chan<- *Event
	conn         int
	seq          uint32
	mu           sync.Mutex
	done         chan struct{}
	started      bool
	pollFallback bool
	poller       *ProcessMonitor
}

func NewLinuxProcMonitor(eventCh chan<- *Event) *LinuxProcMonitor {
	return &LinuxProcMonitor{
		eventCh: eventCh,
		done:    make(chan struct{}),
	}
}

func (pm *LinuxProcMonitor) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.started {
		return nil
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		log.Printf("[proc-mon] netlink unavailable: %v. Falling back to /proc polling.", err)
		log.Printf("[proc-mon] to enable real-time process monitoring: setcap cap_net_admin=ep ./trace-agent or run as root")
		return pm.startFallback()
	}

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: cnIdxProc,
		Pid:    uint32(os.Getpid()),
	}

	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return pm.startFallback()
	}

	if err := pm.sendListen(fd); err != nil {
		unix.Close(fd)
		return pm.startFallback()
	}

	pm.conn = fd
	pm.started = true
	pm.pollFallback = false

	go pm.readLoop()

	log.Printf("[proc-mon] netlink active (real-time)")
	return nil
}

func (pm *LinuxProcMonitor) startFallback() error {
	log.Printf("[proc-mon] falling back to /proc polling (10s)")
	pm.poller = NewProcessMonitor(pm.eventCh)
	pm.pollFallback = true
	pm.started = true
	return nil
}

func (pm *LinuxProcMonitor) sendListen(fd int) error {
	pm.mu.Lock()
	pm.seq++
	seq := pm.seq
	pm.mu.Unlock()

	msg := pm.packMsg(cnIdxProc, cnValProc, seq, nil)
	return unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func (pm *LinuxProcMonitor) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.started {
		close(pm.done)
		if !pm.pollFallback && pm.conn > 0 {
			unix.Close(pm.conn)
		}
	}
}

func (pm *LinuxProcMonitor) readLoop() {
	buf := make([]byte, 65536)
	for {
		select {
		case <-pm.done:
			return
		default:
		}

		n, err := unix.Read(pm.conn, buf)
		if err != nil {
			if err != unix.EINTR {
				log.Printf("[proc-mon] read error: %v", err)
				return
			}
			continue
		}

		pm.process(buf[:n])
	}
}

func (pm *LinuxProcMonitor) process(data []byte) {
	r := bytes.NewReader(data)
	for r.Len() > 0 {
		var nlh struct {
			Len   uint32
			Type  uint16
			Flags uint16
			Seq   uint32
			Pid   uint32
		}
		binary.Read(r, binary.LittleEndian, &nlh)
		if nlh.Type == 0x3 || nlh.Type == 0x2 {
			break
		}
		payloadLen := int(nlh.Len) - int(unsafe.Sizeof(nlh))
		if payloadLen <= 0 || payloadLen > r.Len() {
			break
		}
		payload := make([]byte, payloadLen)
		r.Read(payload)
		pm.parseCN(payload)
	}
}

func (pm *LinuxProcMonitor) parseCN(data []byte) {
	const cnHdrLen = 20
	if len(data) < cnHdrLen+int(unsafe.Sizeof(procEventHdr{})) {
		return
	}

	msgData := data[cnHdrLen:]
	var hdr procEventHdr
	binary.Read(bytes.NewReader(msgData), binary.LittleEndian, &hdr)
	evtData := msgData[unsafe.Sizeof(procEventHdr{}):]

	switch hdr.EventType {
	case procEventFork:
		pm.handleFork(evtData)
	}
}

func (pm *LinuxProcMonitor) handleFork(data []byte) {
	if len(data) < int(unsafe.Sizeof(forkEvent{})) {
		return
	}
	var e forkEvent
	binary.Read(bytes.NewReader(data), binary.LittleEndian, &e)

	name, cmdline := readLinuxProc(int(e.ChildPID))
	evt := &Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Type:      EventProcessCreate,
		Severity:  classifyProcSeverity(name),
		Process: &ProcessInfo{
			PID:     int(e.ChildPID),
			PPID:    int(e.ParentPID),
			Name:    name,
			CmdLine: cmdline,
		},
	}
	if evt.Severity >= SeverityWarning {
		evt.Annotations = map[string]string{"source": "netlink"}
	}
	select {
	case pm.eventCh <- evt:
	default:
	}
}

func readLinuxProc(pid int) (string, string) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "unknown", ""
	}
	f := bytes.Fields(stat)
	name := "unknown"
	if len(f) >= 2 {
		name = string(bytes.Trim(f[1], "()"))
	}
	cmd := ""
	if cd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cmd = string(bytes.ReplaceAll(cd, []byte{0}, []byte(" ")))
	}
	return name, cmd
}

func classifyProcSeverity(name string) Severity {
	for _, s := range suspiciousProcesses {
		if len(name) >= len(s) {
			for i := 0; i <= len(name)-len(s); i++ {
				if name[i:i+len(s)] == s {
					return SeverityWarning
				}
			}
		}
	}
	return SeverityInfo
}

func (pm *LinuxProcMonitor) packMsg(idx, val, seq uint32, data []byte) []byte {
	cnLen := 20
	payloadLen := cnLen
	if data != nil {
		payloadLen += len(data)
	}
	total := unix.NLMSG_HDRLEN + payloadLen
	buf := make([]byte, total)

	nl := (*struct {
		Len   uint32
		Type  uint16
		Flags uint16
		Seq   uint32
		Pid   uint32
	})(unsafe.Pointer(&buf[0]))
	nl.Len = uint32(total)
	nl.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK
	nl.Seq = seq

	cn := (*cnMsg)(unsafe.Pointer(&buf[unix.NLMSG_HDRLEN]))
	cn.ID.Idx = idx
	cn.ID.Val = val
	cn.Seq = seq

	return buf
}
