package monitor

import (
	"fmt"
	"strings"
	"sync"
)

type ProcNode struct {
	PID      int
	PPID     int
	Name     string
	CmdLine  string
	Children []*ProcNode
	Depth    int
}

type ProcessTree struct {
	mu     sync.Mutex
	roots  []*ProcNode
	byPID  map[int]*ProcNode
	maxAge int
}

func NewProcessTree() *ProcessTree {
	return &ProcessTree{
		byPID:  make(map[int]*ProcNode),
		maxAge: 1000,
	}
}

func (t *ProcessTree) Insert(evt *Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if evt.Process == nil {
		return
	}
	pid := evt.Process.PID
	ppid := evt.Process.PPID
	switch evt.Type {
	case EventProcessCreate:
		node := &ProcNode{
			PID:     pid,
			PPID:    ppid,
			Name:    evt.Process.Name,
			CmdLine: evt.Process.CmdLine,
		}
		t.byPID[pid] = node
		if parent, ok := t.byPID[ppid]; ok {
			parent.Children = append(parent.Children, node)
			node.Depth = parent.Depth + 1
		} else {
			node.Depth = 0
			t.roots = append(t.roots, node)
		}
	case EventProcessTerminate:
		delete(t.byPID, pid)
	}
	t.pruneLocked()
}

func (t *ProcessTree) pruneLocked() {
	if len(t.byPID) > t.maxAge {
		for pid, node := range t.byPID {
			if node.Depth > 10 {
				delete(t.byPID, pid)
			}
		}
	}
}

func (t *ProcessTree) GetAncestors(pid int) []*ProcNode {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ancestors []*ProcNode
	current, ok := t.byPID[pid]
	if !ok {
		return nil
	}
	visited := map[int]bool{}
	for current != nil && !visited[current.PID] {
		visited[current.PID] = true
		ancestors = append(ancestors, current)
		if parent, ok := t.byPID[current.PPID]; ok {
			current = parent
		} else {
			break
		}
	}
	return ancestors
}

func (t *ProcessTree) DetectSuspiciousAncestry() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var alerts []string
	suspiciousParents := map[string][]string{
		"winword.exe":  {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe"},
		"excel.exe":    {"powershell.exe", "cmd.exe"},
		"outlook.exe":  {"powershell.exe", "wscript.exe"},
		"chrome.exe":   {"cmd.exe", "powershell.exe"},
		"firefox.exe":  {"cmd.exe", "powershell.exe"},
		"explorer.exe": {"powershell.exe", "cmd.exe", "wscript.exe"},
	}
	for _, node := range t.byPID {
		ppid := node.PPID
		if parent, ok := t.byPID[ppid]; ok {
			parentName := strings.ToLower(parent.Name)
			childName := strings.ToLower(node.Name)
			if badChildren, hasParent := suspiciousParents[parentName]; hasParent {
				for _, bad := range badChildren {
					if childName == bad {
						alerts = append(alerts, fmt.Sprintf(
							"suspicious ancestry: %s (PID %d) spawned %s (PID %d)",
							parent.Name, parent.PID, node.Name, node.PID))
					}
				}
			}
		}
	}
	return alerts
}

func (t *ProcessTree) Format() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var b strings.Builder
	var walk func(node *ProcNode, prefix string)
	walk = func(node *ProcNode, prefix string) {
		b.WriteString(fmt.Sprintf("%s├── %s (PID %d, PPID %d, depth %d)\n",
			prefix, node.Name, node.PID, node.PPID, node.Depth))
		for i, child := range node.Children {
			childPrefix := prefix + "│   "
			if i == len(node.Children)-1 {
				childPrefix = prefix + "    "
			}
			walk(child, childPrefix)
		}
	}
	for _, root := range t.roots {
		walk(root, "")
	}
	return b.String()
}
