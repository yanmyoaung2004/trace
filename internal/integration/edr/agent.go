package edr

import (
	"context"
	"fmt"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type Agent struct {
	client *EDRClient
}

func NewAgentFromConfig(cfg Config) *Agent {
	return &Agent{client: New(cfg)}
}

func (a *Agent) Name() string { return "edr" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "get_agent_info", Inputs: []string{"hostname"}, Outputs: []string{"id", "status", "platform"}},
		{Action: "isolate_host", Inputs: []string{"hostname"}, Outputs: []string{"task_id"}},
		{Action: "release_host", Inputs: []string{"hostname"}, Outputs: []string{"task_id"}},
		{Action: "kill_process", Inputs: []string{"hostname", "pid"}, Outputs: []string{"status"}},
		{Action: "scan_host", Inputs: []string{"hostname"}, Outputs: []string{"task_id"}},
		{Action: "run_script", Inputs: []string{"hostname", "script"}, Outputs: []string{"task_id"}},
	}
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "get_agent_info":
		hostname, _ := input["hostname"].(string)
		if hostname == "" {
			return agent.Output{"error": "hostname is required"}, nil
		}
		info, err := a.client.GetAgentInfo(ctx, hostname)
		if err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		return agent.Output{
			"id":       info.ID,
			"hostname": info.Hostname,
			"status":   info.Status,
			"platform": info.Platform,
			"ip":       info.IPAddress,
			"last_seen": info.LastSeen,
		}, nil

	case "isolate_host":
		hostname, _ := input["hostname"].(string)
		if hostname == "" {
			return agent.Output{"error": "hostname is required"}, nil
		}
		info, err := a.client.GetAgentInfo(ctx, hostname)
		if err != nil {
			return agent.Output{"error": fmt.Sprintf("find host: %v", err)}, nil
		}
		taskID, err := a.client.IsolateHost(ctx, info.ID)
		if err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		return agent.Output{"task_id": taskID, "agent_id": info.ID, "hostname": hostname, "action": "isolate"}, nil

	case "release_host":
		hostname, _ := input["hostname"].(string)
		if hostname == "" {
			return agent.Output{"error": "hostname is required"}, nil
		}
		info, err := a.client.GetAgentInfo(ctx, hostname)
		if err != nil {
			return agent.Output{"error": fmt.Sprintf("find host: %v", err)}, nil
		}
		taskID, err := a.client.ReleaseHost(ctx, info.ID)
		if err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		return agent.Output{"task_id": taskID, "agent_id": info.ID, "hostname": hostname, "action": "release"}, nil

	case "kill_process":
		hostname, _ := input["hostname"].(string)
		pid := 0
		if p, ok := input["pid"].(float64); ok {
			pid = int(p)
		}
		if hostname == "" || pid == 0 {
			return agent.Output{"error": "hostname and pid are required"}, nil
		}
		info, err := a.client.GetAgentInfo(ctx, hostname)
		if err != nil {
			return agent.Output{"error": fmt.Sprintf("find host: %v", err)}, nil
		}
		if err := a.client.KillProcess(ctx, info.ID, pid); err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		return agent.Output{"status": "killed", "hostname": hostname, "pid": pid}, nil

	case "scan_host":
		hostname, _ := input["hostname"].(string)
		if hostname == "" {
			return agent.Output{"error": "hostname is required"}, nil
		}
		info, err := a.client.GetAgentInfo(ctx, hostname)
		if err != nil {
			return agent.Output{"error": fmt.Sprintf("find host: %v", err)}, nil
		}
		taskID, err := a.client.ScanHost(ctx, info.ID)
		if err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		return agent.Output{"task_id": taskID, "hostname": hostname, "action": "scan"}, nil

	case "run_script":
		hostname, _ := input["hostname"].(string)
		script, _ := input["script"].(string)
		if hostname == "" || script == "" {
			return agent.Output{"error": "hostname and script are required"}, nil
		}
		info, err := a.client.GetAgentInfo(ctx, hostname)
		if err != nil {
			return agent.Output{"error": fmt.Sprintf("find host: %v", err)}, nil
		}
		taskID, err := a.client.RunScript(ctx, info.ID, script)
		if err != nil {
			return agent.Output{"error": err.Error()}, nil
		}
		return agent.Output{"task_id": taskID, "hostname": hostname, "action": "run_script"}, nil

	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}
