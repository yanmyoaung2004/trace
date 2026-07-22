package monitor

import (
	"container/list"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ProcNode struct {
	PID      int         `json:"pid"`
	PPID     int         `json:"ppid"`
	Name     string      `json:"name"`
	CmdLine  string      `json:"cmdline,omitempty"`
	Children []*ProcNode `json:"children,omitempty"`
	Depth    int         `json:"depth"`
	StartAt  time.Time   `json:"start_at"`
	EndAt    *time.Time  `json:"end_at,omitempty"`
}

type ProcessTree struct {
	mu       sync.RWMutex
	byPID    map[int]*list.Element
	lruList  *list.List
	maxNodes int
	dataDir  string
}

type lruEntry struct {
	pid  int
	node *ProcNode
}

func NewProcessTree(dataDir string) *ProcessTree {
	t := &ProcessTree{
		byPID:    make(map[int]*list.Element),
		lruList:  list.New(),
		maxNodes: 100000,
		dataDir:  dataDir,
	}
	t.load()
	return t
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
		if _, exists := t.byPID[pid]; exists {
			t.touchLocked(pid)
			return
		}
		node := &ProcNode{
			PID: pid, PPID: ppid,
			Name: evt.Process.Name, CmdLine: evt.Process.CmdLine,
			Depth: 0, StartAt: time.Now(),
		}
		if parentElem, ok := t.byPID[ppid]; ok {
			parent := parentElem.Value.(*lruEntry).node
			parent.Children = append(parent.Children, node)
			node.Depth = parent.Depth + 1
		}
		elem := t.lruList.PushFront(&lruEntry{pid: pid, node: node})
		t.byPID[pid] = elem
		t.evictLocked()

	case EventProcessTerminate:
		if elem, ok := t.byPID[pid]; ok {
			entry := elem.Value.(*lruEntry)
			now := time.Now()
			entry.node.EndAt = &now
		}
	}
}

func (t *ProcessTree) touchLocked(pid int) {
	if elem, ok := t.byPID[pid]; ok {
		t.lruList.MoveToFront(elem)
	}
}

func (t *ProcessTree) evictLocked() {
	for t.lruList.Len() > t.maxNodes {
		elem := t.lruList.Back()
		if elem == nil {
			break
		}
		entry := elem.Value.(*lruEntry)
		// Keep if still running and depth < 3
		if entry.node.EndAt == nil && entry.node.Depth < 3 {
			t.lruList.MoveToFront(elem)
			if t.lruList.Len() <= t.maxNodes {
				break
			}
			elem = t.lruList.Back()
			if elem == nil {
				break
			}
			entry = elem.Value.(*lruEntry)
		}
		delete(t.byPID, entry.pid)
		t.lruList.Remove(elem)
	}
}

func (t *ProcessTree) GetAncestors(pid int) []*ProcNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var ancestors []*ProcNode
	elem, ok := t.byPID[pid]
	if !ok {
		return nil
	}
	visited := map[int]bool{}
	current := elem.Value.(*lruEntry).node
	for current != nil && !visited[current.PID] {
		visited[current.PID] = true
		ancestors = append(ancestors, current)
		if parentElem, ok := t.byPID[current.PPID]; ok {
			current = parentElem.Value.(*lruEntry).node
		} else {
			break
		}
	}
	return ancestors
}

func (t *ProcessTree) DetectSuspiciousAncestry() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var alerts []string
	suspiciousParents := map[string][]string{
		"winword.exe":  {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe"},
		"excel.exe":    {"powershell.exe", "cmd.exe"},
		"outlook.exe":  {"powershell.exe", "wscript.exe"},
		"chrome.exe":   {"cmd.exe", "powershell.exe"},
		"firefox.exe":  {"cmd.exe", "powershell.exe"},
		"explorer.exe": {"powershell.exe", "cmd.exe", "wscript.exe"},
	}
	for _, elem := range t.byPID {
		entry := elem.Value.(*lruEntry)
		node := entry.node
		if parentElem, ok := t.byPID[node.PPID]; ok {
			parent := parentElem.Value.(*lruEntry).node
			pName := strings.ToLower(parent.Name)
			cName := strings.ToLower(node.Name)
			if badChildren, has := suspiciousParents[pName]; has {
				for _, bad := range badChildren {
					if cName == bad {
						alerts = append(alerts, fmt.Sprintf(
							"suspicious ancestry: %s(PID:%d) spawned %s(PID:%d)",
							parent.Name, parent.PID, node.Name, node.PID))
					}
				}
			}
		}
	}
	return alerts
}

func (t *ProcessTree) Save() error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.dataDir == "" {
		return nil
	}
	nodes := make([]*ProcNode, 0, len(t.byPID))
	for _, elem := range t.byPID {
		nodes = append(nodes, elem.Value.(*lruEntry).node)
		if len(nodes) >= 10000 {
			break
		}
	}
	data, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	path := filepath.Join(t.dataDir, "process_tree.json")
	os.MkdirAll(t.dataDir, 0700)
	os.WriteFile(path, data, 0600)
	log.Printf("[tree] saved %d nodes", len(nodes))
	return nil
}

func (t *ProcessTree) load() {
	if t.dataDir == "" {
		return
	}
	path := filepath.Join(t.dataDir, "process_tree.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var nodes []*ProcNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, node := range nodes {
		if _, exists := t.byPID[node.PID]; exists {
			continue
		}
		elem := t.lruList.PushFront(&lruEntry{pid: node.PID, node: node})
		t.byPID[node.PID] = elem
	}
	// Rebuild parent-child relationships
	for _, node := range nodes {
		if parentElem, ok := t.byPID[node.PPID]; ok {
			parent := parentElem.Value.(*lruEntry).node
			already := false
			for _, c := range parent.Children {
				if c.PID == node.PID {
					already = true
					break
				}
			}
			if !already {
				parent.Children = append(parent.Children, node)
				node.Depth = parent.Depth + 1
			}
		}
	}
	log.Printf("[tree] loaded %d nodes from disk", len(nodes))
}

func (t *ProcessTree) Format() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var b strings.Builder
	var walk func(node *ProcNode, prefix string)
	walk = func(node *ProcNode, prefix string) {
		status := "running"
		if node.EndAt != nil {
			status = "dead"
		}
		b.WriteString(fmt.Sprintf("%s├── %s(PID:%d,PPID:%d,depth:%d,%s)\n",
			prefix, node.Name, node.PID, node.PPID, node.Depth, status))
		for i, child := range node.Children {
			childPrefix := prefix + "│   "
			if i == len(node.Children)-1 {
				childPrefix = prefix + "    "
			}
			walk(child, childPrefix)
		}
	}
	for _, elem := range t.byPID {
		entry := elem.Value.(*lruEntry)
		if entry.node.PPID == 0 || entry.node.PPID == entry.node.PID {
			walk(entry.node, "")
		}
	}
	return b.String()
}
