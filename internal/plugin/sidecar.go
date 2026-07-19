package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type sidecarRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type sidecarResponse struct {
	ID    string `json:"id"`
	Result any   `json:"result,omitempty"`
	Error string `json:"error,omitempty"`
}

type SidecarPlugin struct {
	Name           string
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	reader         *bufio.Reader
	CapabilityDefs []agent.Capability
}

func LoadSidecar(path string, args []string) (*SidecarPlugin, error) {
	cmd := exec.Command(path, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("sidecar stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("sidecar stdout: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("sidecar stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sidecar start: %w", err)
	}

	go func() {
		io.Copy(io.Discard, stderr)
	}()

	reader := bufio.NewReader(stdout)

	sp := &SidecarPlugin{
		cmd:    cmd,
		stdin:  stdin,
		reader: reader,
	}

	info, err := sp.call("info", nil, 5*time.Second)
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("sidecar info: %w", err)
	}

	infoMap, ok := info.(map[string]any)
	if !ok {
		cmd.Process.Kill()
		return nil, fmt.Errorf("sidecar info: invalid response format")
	}

	name, _ := infoMap["name"].(string)
	if name == "" {
		cmd.Process.Kill()
		return nil, fmt.Errorf("sidecar: name is required")
	}
	sp.Name = name

	caps, _ := infoMap["capabilities"].([]any)
	for _, c := range caps {
		if cm, ok := c.(map[string]any); ok {
			action, _ := cm["action"].(string)
			if action != "" {
				capDef := agent.Capability{Action: action}
				sp.CapabilityDefs = append(sp.CapabilityDefs, capDef)
			}
		}
	}

	return sp, nil
}

func (sp *SidecarPlugin) call(method string, params any, timeout time.Duration) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := sidecarRequest{
		ID:     fmt.Sprintf("req-%d", time.Now().UnixNano()),
		Method: method,
		Params: params,
	}

	data, _ := json.Marshal(req)
	if _, err := sp.stdin.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("sidecar write: %w", err)
	}

	responseCh := make(chan sidecarResponse, 1)
	errCh := make(chan error, 1)

	go func() {
		line, err := sp.reader.ReadString('\n')
		if err != nil {
			errCh <- fmt.Errorf("sidecar read: %w", err)
			return
		}

		var resp sidecarResponse
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &resp); err != nil {
			errCh <- fmt.Errorf("sidecar parse: %w", err)
			return
		}
		responseCh <- resp
	}()

	select {
	case resp := <-responseCh:
		if resp.Error != "" {
			return nil, fmt.Errorf("sidecar error: %s", resp.Error)
		}
		return resp.Result, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("sidecar timeout")
	}
}

func (sp *SidecarPlugin) Execute(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	req := map[string]any{
		"action": action,
		"params": params,
	}

	result, err := sp.call("execute", req, 30*time.Second)
	if err != nil {
		return nil, err
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sidecar: invalid result format")
	}
	return resultMap, nil
}

func (sp *SidecarPlugin) Capabilities() []agent.Capability {
	return sp.CapabilityDefs
}

func (sp *SidecarPlugin) Stop() {
	if sp.cmd != nil && sp.cmd.Process != nil {
		sp.cmd.Process.Signal(execCmdStopSignal())
		go func() {
			time.AfterFunc(5*time.Second, func() { sp.cmd.Process.Kill() })
		}()
	}
}

func execCmdStopSignal() osSignal {
	return execCmdStop
}
