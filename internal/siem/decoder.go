package siem

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Decoder interface {
	Name() string
	Decode(raw []byte) (*Event, error)
}

var (
	apacheCombinedRe = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)`)
	apacheErrorRe    = regexp.MustCompile(`^\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\[client\s+([^\]]+)\])?\s*(.*)$`)
	syslogRFC3164Re  = regexp.MustCompile(`^<(\d+)>?(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\s+(.*)$`)
	winEventRe       = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\(([^)]+)\)\s+(.*)$`)
	jsonLogPrefixRe  = regexp.MustCompile(`^\s*[{[]`)
)

type JSONDecoder struct{}

func (d *JSONDecoder) Name() string { return "json" }

func (d *JSONDecoder) Decode(raw []byte) (*Event, error) {
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	e := &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:json",
		Raw:       string(raw),
		Fields:    fields,
	}

	if ts, ok := fields["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			e.Timestamp = t.UTC()
		}
	} else if ts, ok := fields["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			e.Timestamp = t.UTC()
		} else if t, err := time.Parse("2006-01-02T15:04:05", ts); err == nil {
			e.Timestamp = t.UTC()
		}
	}

	if sev, ok := fields["severity"].(float64); ok {
		e.Severity = int(sev)
	} else if level, ok := fields["level"].(string); ok {
		e.Severity = levelToSeverity(level)
	}

	if src, ok := fields["source"].(string); ok {
		e.Tags = append(e.Tags, "source:"+src)
	}

	return e, nil
}

type ApacheDecoder struct{}

func (d *ApacheDecoder) Name() string { return "apache" }

func (d *ApacheDecoder) Decode(raw []byte) (*Event, error) {
	m := apacheCombinedRe.FindSubmatch(raw)
	if m == nil {
		return nil, fmt.Errorf("not apache combined format")
	}

	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700", string(m[2]))

	e := &Event{
		Timestamp: ts.UTC(),
		Source:    "decoder:apache",
		Raw:       string(raw),
		Fields: map[string]any{
			"client_ip":  string(m[1]),
			"method":     string(m[3]),
			"path":       string(m[4]),
			"status":     parseInt(string(m[5])),
			"bytes":      parseInt(string(m[6])),
			"event_type": "http_request",
		},
	}

	status := parseInt(string(m[5]))
	if status >= 500 {
		e.Severity = 3
		e.Tags = append(e.Tags, "http_error")
	} else if status >= 400 {
		e.Severity = 2
		e.Tags = append(e.Tags, "http_client_error")
	} else if status >= 300 {
		e.Tags = append(e.Tags, "http_redirect")
	} else {
		e.Tags = append(e.Tags, "http_success")
	}

	return e, nil
}

type SyslogDecoder struct{}

func (d *SyslogDecoder) Name() string { return "syslog" }

func (d *SyslogDecoder) Decode(raw []byte) (*Event, error) {
	m := syslogRFC3164Re.FindSubmatch(raw)
	if m == nil {
		return &Event{
			Timestamp: time.Now().UTC(),
			Source:    "decoder:syslog",
			Raw:       string(raw),
			Fields:    map[string]any{"message": string(raw)},
		}, nil
	}

	e := &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:syslog",
		Raw:       string(raw),
		Fields: map[string]any{
			"facility":  parseInt(string(m[1])),
			"timestamp": string(m[2]),
			"hostname":  string(m[3]),
			"app":       string(m[4]),
			"message":   string(m[5]),
		},
	}

	if ts, err := time.Parse("Jan _2 15:04:05", string(m[2])); err == nil {
		e.Timestamp = ts.UTC()
	}

	msg := string(m[5])
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure"):
		e.Severity = 3
		e.Tags = append(e.Tags, "auth_failure", "security")
	case strings.Contains(lower, "accepted password"):
		e.Tags = append(e.Tags, "auth_success", "security")
	case strings.Contains(lower, "error") || strings.Contains(lower, "panic"):
		e.Severity = 2
		e.Tags = append(e.Tags, "error")
	case strings.Contains(lower, "warn"):
		e.Severity = 1
		e.Tags = append(e.Tags, "warning")
	}

	return e, nil
}

type CSVDecoder struct {
	Fields []string
}

func (d *CSVDecoder) Name() string { return "csv" }

func (d *CSVDecoder) Decode(raw []byte) (*Event, error) {
	line := strings.TrimRight(string(raw), "\r\n")
	parts := strings.Split(line, ",")

	fields := make(map[string]any, len(parts))
	for i, val := range parts {
		val = strings.TrimSpace(val)
		if i < len(d.Fields) {
			fields[d.Fields[i]] = val
		} else {
			fields[fmt.Sprintf("field_%d", i)] = val
		}
	}

	return &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:csv",
		Raw:       string(raw),
		Fields:    fields,
	}, nil
}

type WindowsEventDecoder struct{}

func (d *WindowsEventDecoder) Name() string { return "windows_event" }

func (d *WindowsEventDecoder) Decode(raw []byte) (*Event, error) {
	m := winEventRe.FindSubmatch(raw)
	if m == nil {
		return nil, fmt.Errorf("not windows event format")
	}

	e := &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:windows_event",
		Raw:       string(raw),
		Fields: map[string]any{
			"date":    string(m[1]),
			"time":    string(m[2]),
			"source":  string(m[3]),
			"message": string(m[4]),
		},
	}

	if ts, err := time.Parse("2006/01/02 15:04:05", string(m[1])+" "+string(m[2])); err == nil {
		e.Timestamp = ts.UTC()
	}

	msg := strings.ToLower(string(m[4]))
	if strings.Contains(msg, "4625") || strings.Contains(msg, "failed logon") || strings.Contains(msg, "logon failure") {
		e.Severity = 3
		e.Tags = append(e.Tags, "security", "auth_failure")
		e.Fields["logontype"] = extractLogonType(string(m[4]))
	} else if strings.Contains(msg, "4624") || strings.Contains(msg, "logon success") {
		e.Tags = append(e.Tags, "security", "auth_success")
	} else if strings.Contains(msg, "4688") || strings.Contains(msg, "process creation") {
		e.Tags = append(e.Tags, "security", "process_creation")
		e.Fields["process_path"] = extractField(string(m[4]), "process:")
	} else if strings.Contains(msg, "4698") || strings.Contains(msg, "scheduled task") {
		e.Tags = append(e.Tags, "security", "persistence")
		e.Severity = 3
	} else if strings.Contains(msg, "7045") || strings.Contains(msg, "service install") {
		e.Tags = append(e.Tags, "security", "service_install")
		e.Severity = 3
	} else if strings.Contains(msg, "1116") || strings.Contains(msg, "defender") {
		e.Tags = append(e.Tags, "security", "malware_detection")
		e.Severity = 5
		e.Fields["file_path"] = extractField(string(m[4]), "file:")
	} else if strings.Contains(msg, "4104") || strings.Contains(msg, "powershell") {
		e.Tags = append(e.Tags, "security", "powershell")
		e.Severity = 2
	} else if strings.Contains(msg, "4657") || strings.Contains(msg, "registry") {
		e.Tags = append(e.Tags, "security", "registry_change")
		e.Severity = 2
	} else if strings.Contains(msg, "4740") || strings.Contains(msg, "locked out") {
		e.Tags = append(e.Tags, "security", "account_lockout")
		e.Severity = 3
	} else if strings.Contains(msg, "error") {
		e.Severity = 2
		e.Tags = append(e.Tags, "error")
	}

	e.Fields["event_id"] = m[2]

	return e, nil
}

type AutoDecoder struct{}

func (d *AutoDecoder) Name() string { return "auto" }

func (d *AutoDecoder) Decode(raw []byte) (*Event, error) {
	decoders := []Decoder{
		&JSONDecoder{},
		&ApacheDecoder{},
		&SyslogDecoder{},
		&WindowsEventDecoder{},
	}

	for _, dec := range decoders {
		event, err := dec.Decode(raw)
		if err == nil {
			return event, nil
		}
	}

	return &Event{
		Timestamp: time.Now().UTC(),
		Source:    "decoder:raw",
		Raw:       string(raw),
		Fields:    map[string]any{"message": string(raw)},
	}, nil
}

func extractLogonType(msg string) string {
	if strings.Contains(msg, "logontype: 10") || strings.Contains(msg, "logon type: 10") {
		return "10"
	}
	if strings.Contains(msg, "logontype: 2") || strings.Contains(msg, "logon type: 2") {
		return "2"
	}
	if strings.Contains(msg, "logontype: 3") || strings.Contains(msg, "logon type: 3") {
		return "3"
	}
	return ""
}

func extractField(msg, prefix string) string {
	idx := strings.Index(strings.ToLower(msg), prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	for start < len(msg) && msg[start] == ' ' {
		start++
	}
	end := start
	for end < len(msg) && msg[end] != ',' && msg[end] != ' ' && msg[end] != '\n' {
		end++
	}
	if end > start {
		return msg[start:end]
	}
	return ""
}

func parseInt(s string) int {
	if s == "" || s == "-" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func levelToSeverity(level string) int {
	switch strings.ToLower(level) {
	case "critical", "fatal", "emergency":
		return 5
	case "error":
		return 4
	case "warn", "warning":
		return 3
	case "info":
		return 1
	case "debug", "trace":
		return 0
	default:
		return 2
	}
}
