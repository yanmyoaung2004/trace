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

	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}
