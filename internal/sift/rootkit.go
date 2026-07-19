package sift

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type rootkitFileEntry struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name"`
	Ref     string `json:"ref"`
}

type trojanEntry struct {
	Binary      string `json:"binary"`
	Signature   string `json:"signature"`
	Description string `json:"description"`
}

type RootkitScanner struct {
	files     []rootkitFileEntry
	trojans   []trojanEntry
	compiled  map[string]*regexp.Regexp
}

func NewRootkitScanner() *RootkitScanner {
	s := &RootkitScanner{compiled: make(map[string]*regexp.Regexp)}

	json.Unmarshal([]byte(rootkitFilesJSON), &s.files)
	json.Unmarshal([]byte(rootkitTrojanJSON), &s.trojans)

	for _, t := range s.trojans {
		if re, err := regexp.Compile(t.Signature); err == nil {
			s.compiled[t.Binary] = re
		}
	}

	return s
}

func (s *RootkitScanner) Name() string { return "rootkit" }

func (s *RootkitScanner) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "scan_rootkits", Inputs: []string{"path"}, Outputs: []string{"matches", "count"}},
		{Action: "check_trojans", Inputs: []string{"binary"}, Outputs: []string{"matches", "count"}},
		{Action: "behavior_scan", Inputs: []string{}, Outputs: []string{"results", "suspicious_count", "total_checks"}},
	}
}

func (s *RootkitScanner) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "scan_rootkits":
		return s.scanRootkits(ctx, input)
	case "check_trojans":
		return s.checkTrojan(ctx, input)
	case "behavior_scan":
		return s.behaviorScan(ctx)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (s *RootkitScanner) behaviorScan(ctx context.Context) (agent.Output, error) {
	results := RunBehaviorChecks(ctx)
	suspicious := 0
	for _, r := range results {
		if status, _ := r["status"].(string); status == "suspicious" {
			suspicious++
		}
	}
	return agent.Output{
		"results":         results,
		"suspicious_count": suspicious,
		"total_checks":    len(results),
	}, nil
}

func (s *RootkitScanner) scanRootkits(ctx context.Context, input agent.Input) (agent.Output, error) {
	path, _ := input["path"].(string)
	if path == "" {
		path, _ = input["dir"].(string)
	}

	var globalPatterns []rootkitFileEntry
	var localPatterns []rootkitFileEntry

	for _, rk := range s.files {
		if strings.HasPrefix(rk.Pattern, "*") {
			globalPatterns = append(globalPatterns, rk)
		} else {
			localPatterns = append(localPatterns, rk)
		}
	}

	var matches []map[string]string
	visited := make(map[string]bool)

	scanFile := func(fullPath string) {
		if visited[fullPath] {
			return
		}
		visited[fullPath] = true
		for _, rk := range globalPatterns {
			pattern := strings.TrimPrefix(rk.Pattern, "*")
			if strings.Contains(fullPath, pattern) {
				matches = append(matches, map[string]string{
					"file":    fullPath,
					"name":    rk.Name,
					"pattern": rk.Pattern,
					"ref":     rk.Ref,
				})
				return
			}
		}
	}

	walkFn := func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			for _, rk := range localPatterns {
				if strings.Contains(p, rk.Pattern) {
					matches = append(matches, map[string]string{
						"file":    p,
						"name":    rk.Name,
						"pattern": rk.Pattern,
						"ref":     rk.Ref,
						"type":    "directory",
					})
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		scanFile(p)
		for _, rk := range localPatterns {
			if strings.Contains(p, rk.Pattern) {
				matches = append(matches, map[string]string{
					"file":    p,
					"name":    rk.Name,
					"pattern": rk.Pattern,
					"ref":     rk.Ref,
					"type":    "file",
				})
				return nil
			}
		}
		return nil
	}

	if path != "" {
		if err := filepath.Walk(path, walkFn); err != nil {
			return agent.Output{"error": err.Error(), "count": len(matches), "matches": matches}, nil
		}
	}

	if len(globalPatterns) > 0 {
		for _, root := range getSystemRoots() {
			if err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				scanFile(p)
				return nil
			}); err != nil {
				continue
			}
		}
	}

	return agent.Output{
		"matches": matches,
		"count":   len(matches),
	}, nil
}

func getSystemRoots() []string {
	if runtime.GOOS == "windows" {
		return []string{"C:\\Windows\\System32", "C:\\Windows\\SysWOW64", "C:\\ProgramData"}
	}
	return []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp", "/dev/shm", "/lib", "/usr/lib"}
}

func (s *RootkitScanner) checkTrojan(ctx context.Context, input agent.Input) (agent.Output, error) {
	binary, _ := input["binary"].(string)
	if binary == "" {
		binary, _ = input["name"].(string)
	}
	if binary == "" {
		return agent.Output{"error": "binary name is required", "count": 0}, nil
	}

	binName := filepath.Base(binary)

	re, ok := s.compiled[binName]
	if !ok {
		for _, t := range s.trojans {
			if strings.Contains(binName, t.Binary) || strings.Contains(t.Binary, binName) {
				re = s.compiled[t.Binary]
				break
			}
		}
	}
	if re == nil {
		return agent.Output{"binary": binName, "verdict": "clean", "count": 0}, nil
	}

	data, err := os.ReadFile(binary)
	if err != nil {
		return agent.Output{"binary": binName, "error": fmt.Sprintf("read failed: %v", err), "count": 0}, nil
	}

	if re.Match(data) {
		return agent.Output{
			"binary":  binName,
			"verdict": "trojaned",
			"count":   1,
		}, nil
	}

	return agent.Output{"binary": binName, "verdict": "clean", "count": 0}, nil
}
