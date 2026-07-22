package monitor

import "time"

type EventType string

const (
	EventProcessCreate   EventType = "process_create"
	EventProcessTerminate EventType = "process_terminate"
	EventFileCreate      EventType = "file_create"
	EventFileModify      EventType = "file_modify"
	EventFileDelete      EventType = "file_delete"
	EventNetConnect      EventType = "net_connect"
	EventNetListen       EventType = "net_listen"
	EventNetDisconnect   EventType = "net_disconnect"
	EventRegistryChange  EventType = "registry_change"
	EventAlert           EventType = "alert"
	EventSystemSnapshot  EventType = "system_snapshot"
)

type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityWarning  Severity = 3
	SeverityAlert    Severity = 5
	SeverityCritical Severity = 7
)

type Event struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Type        EventType         `json:"type"`
	Severity    Severity          `json:"severity"`
	Process     *ProcessInfo      `json:"process,omitempty"`
	File        *FileInfo         `json:"file,omitempty"`
	Network     *NetInfo          `json:"network,omitempty"`
	Registry    *RegistryInfo     `json:"registry,omitempty"`
	System      *SnapshotInfo     `json:"system,omitempty"`
	Raw         map[string]any    `json:"raw,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ProcessInfo struct {
	PID       int     `json:"pid"`
	PPID      int     `json:"ppid,omitempty"`
	Name      string  `json:"name"`
	Path      string  `json:"path,omitempty"`
	CmdLine   string  `json:"cmdline,omitempty"`
	User      string  `json:"user,omitempty"`
	Hash      string  `json:"hash,omitempty"`
	CPU       float64 `json:"cpu,omitempty"`
	MemoryMB  int64   `json:"memory_mb,omitempty"`
}

type FileInfo struct {
	Path      string `json:"path"`
	Size      int64  `json:"size,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Owner     string `json:"owner,omitempty"`
}

type NetInfo struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Protocol   string `json:"protocol"`
	PID        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
	Direction  string `json:"direction"`
}

type RegistryInfo struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
	Old   string `json:"old,omitempty"`
	Action string `json:"action"`
}

type SnapshotInfo struct {
	Processes  int `json:"processes"`
	Connections int `json:"connections"`
	Listeners  int `json:"listeners"`
}

type unsupportedError struct{}

func (*unsupportedError) Error() string { return "not supported on this platform" }
