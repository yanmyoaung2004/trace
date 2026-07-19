package siem

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type wazuhDecoderDef struct {
	Name        string   `json:"name"`
	Parent      string   `json:"parent,omitempty"`
	ProgramName string   `json:"program_name,omitempty"`
	PreMatch    string   `json:"prematch,omitempty"`
	Regex       string   `json:"regex,omitempty"`
	Order       []string `json:"order,omitempty"`
}

type compiledNode struct {
	def       wazuhDecoderDef
	preRe     *regexp.Regexp
	regexRe   *regexp.Regexp
	progRe    *regexp.Regexp
	children  []*compiledNode
}

type WazuhDecoder struct {
	roots    []*compiledNode
	byName   map[string]*compiledNode
	initOnce sync.Once
}

func NewWazuhDecoder() *WazuhDecoder {
	return &WazuhDecoder{byName: make(map[string]*compiledNode)}
}

func (wd *WazuhDecoder) Name() string { return "wazuh" }

func (wd *WazuhDecoder) init() {
	wd.initOnce.Do(func() {
		var defs []wazuhDecoderDef
		if err := json.Unmarshal([]byte(wazuhDecodersJSON), &defs); err != nil {
			return
		}

		for _, d := range defs {
			node := &compiledNode{def: d}
			if d.PreMatch != "" {
				node.preRe = compilePattern(d.PreMatch)
			}
			if d.Regex != "" {
				node.regexRe = compilePattern(d.Regex)
			}
			if d.ProgramName != "" {
				node.progRe = compilePattern(d.ProgramName)
			}
			wd.byName[d.Name] = node
		}

		for _, node := range wd.byName {
			if node.def.Parent == "" {
				wd.roots = append(wd.roots, node)
			} else if parent, ok := wd.byName[node.def.Parent]; ok {
				parent.children = append(parent.children, node)
			}
		}
	})
}

func compilePattern(pattern string) *regexp.Regexp {
	p := strings.ReplaceAll(pattern, `\`, `\\`)
	re, err := regexp.Compile(p)
	if err != nil {
		return nil
	}
	return re
}

func (wd *WazuhDecoder) Decode(raw []byte) (*Event, error) {
	wd.init()
	line := string(raw)

	node := wd.findRoot(line)
	if node == nil {
		return nil, fmt.Errorf("no matching decoder")
	}

	fields := make(map[string]any)
	tags := []string{node.def.Name}

	child := wd.findChild(node, line)
	if child != nil {
		tags = append(tags, child.def.Name)
		extractFields(child, line, fields)
	} else if node.regexRe != nil && len(node.def.Order) > 0 {
		extractFields(node, line, fields)
	}

	severity, inferredTags := inferTags(tags, line)
	tags = append(tags, inferredTags...)

	return &Event{
		Timestamp: time.Now(),
		Source:    "wazuh",
		Raw:       line,
		Fields:    fields,
		Tags:      tags,
		Severity:  severity,
	}, nil
}

func extractFields(n *compiledNode, line string, fields map[string]any) {
	if n.regexRe == nil || len(n.def.Order) == 0 {
		return
	}
	matches := n.regexRe.FindStringSubmatch(line)
	if len(matches) <= 1 {
		return
	}
	for i, name := range n.def.Order {
		idx := i + 1
		if idx < len(matches) && matches[idx] != "" {
			fields[name] = matches[idx]
		}
	}
}

func (wd *WazuhDecoder) findRoot(line string) *compiledNode {
	for _, node := range wd.roots {
		if node.progRe != nil && node.progRe.MatchString(line) {
			return node
		}
	}
	for _, node := range wd.roots {
		if node.preRe != nil && node.preRe.MatchString(line) {
			return node
		}
	}
	return nil
}

func (wd *WazuhDecoder) findChild(parent *compiledNode, line string) *compiledNode {
	for _, child := range parent.children {
		if child.preRe != nil && child.preRe.MatchString(line) {
			if child.regexRe == nil || child.regexRe.MatchString(line) {
				return child
			}
		}
	}
	return nil
}

var tagMap = map[string]struct {
	tags     []string
	severity int
}{
	"sshd":            {tags: []string{"sshd"}, severity: 0},
	"sshd-success":    {tags: []string{"auth_success"}, severity: 3},
	"ssh-denied":      {tags: []string{"auth_failure"}, severity: 4},
	"ssh-invfailed":   {tags: []string{"auth_failure"}, severity: 5},
	"ssh-kbd":         {tags: []string{"auth_failure"}, severity: 5},
	"sshd-solaris":    {tags: []string{"auth_success"}, severity: 3},
	"sshd-connection": {tags: []string{"auth_failure"}, severity: 4},
	"sshd-disconnect": {tags: []string{"auth_failure"}, severity: 3},
	"apache-errorlog": {tags: []string{"http_error"}, severity: 3},
	"apache24-errorlog-ip-port":    {tags: []string{"http_error"}, severity: 3},
	"docker":         {tags: []string{"docker"}, severity: 0},
	"docker-container": {tags: []string{"docker"}, severity: 0},
	"paloalto":       {tags: []string{"firewall"}, severity: 0},
	"fortigate":      {tags: []string{"firewall"}, severity: 0},
	"firewalld":      {tags: []string{"firewall"}, severity: 0},
	"sysmon":         {tags: []string{"sysmon"}, severity: 0},
	"windows":        {tags: []string{"windows"}, severity: 0},
	"windows-event-channel": {tags: []string{"windows"}, severity: 0},
	"sudo":           {tags: []string{"auth", "privilege_escalation"}, severity: 3},
	"su":             {tags: []string{"auth", "privilege_escalation"}, severity: 3},
	"named":          {tags: []string{"dns"}, severity: 0},
	"dovecot":        {tags: []string{"mail", "imap"}, severity: 0},
	"postfix":        {tags: []string{"mail", "smtp"}, severity: 0},
	"nginx":          {tags: []string{"http_error"}, severity: 3},
	"apache":         {tags: []string{"http_error"}, severity: 3},
	"mysql":          {tags: []string{"database", "mysql"}, severity: 0},
	"postgresql":     {tags: []string{"database", "postgresql"}, severity: 0},
	"clamd":          {tags: []string{"antivirus"}, severity: 5},
	"win-defender":   {tags: []string{"antivirus", "windows"}, severity: 5},
	"win-security":   {tags: []string{"windows", "security"}, severity: 3},
	"win-system":     {tags: []string{"windows", "system"}, severity: 2},
	"win-app":        {tags: []string{"windows", "application"}, severity: 2},
	"win-powershell": {tags: []string{"powershell"}, severity: 3},
	"auditd":         {tags: []string{"audit", "linux"}, severity: 0},
	"kernel":         {tags: []string{"kernel", "linux"}, severity: 0},
}

func inferTags(decoderNames []string, line string) (int, []string) {
	var tags []string
	severity := 0

	lineLower := strings.ToLower(line)

	for _, name := range decoderNames {
		if entry, ok := tagMap[name]; ok {
			tags = append(tags, entry.tags...)
			if entry.severity > severity {
				severity = entry.severity
			}
		}
	}

	if strings.Contains(lineLower, "error") {
		hasErr := false
		for _, t := range tags {
			if t == "error" {
				hasErr = true
				break
			}
		}
		if !hasErr {
			tags = append(tags, "error")
		}
	}

	return severity, tags
}
