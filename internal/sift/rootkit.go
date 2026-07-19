package sift

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	}
}

func (s *RootkitScanner) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "scan_rootkits":
		return s.scanRootkits(ctx, input)
	case "check_trojans":
		return s.checkTrojan(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (s *RootkitScanner) scanRootkits(ctx context.Context, input agent.Input) (agent.Output, error) {
	path, _ := input["path"].(string)
	if path == "" {
		path, _ = input["dir"].(string)
	}
	if path == "" {
		return agent.Output{"error": "path is required", "count": 0}, nil
	}

	var matches []map[string]string
	walkFn := func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		for _, rk := range s.files {
			pattern := rk.Pattern
			globalSearch := strings.HasPrefix(pattern, "*")
			if globalSearch {
				pattern = strings.TrimPrefix(pattern, "*")
			}
			if strings.Contains(p, pattern) {
				matches = append(matches, map[string]string{
					"file":    p,
					"name":    rk.Name,
					"pattern": rk.Pattern,
					"ref":     rk.Ref,
				})
				break
			}
		}
		return nil
	}

	if err := filepath.Walk(path, walkFn); err != nil {
		return agent.Output{"error": err.Error(), "count": len(matches), "matches": matches}, nil
	}

	return agent.Output{
		"matches": matches,
		"count":   len(matches),
	}, nil
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
