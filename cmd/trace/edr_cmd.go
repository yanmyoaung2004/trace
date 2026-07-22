package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newEDRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edr",
		Short: "Manage EDR agents and dispatch remote actions",
		Long: `Manage EDR agents and dispatch remote actions.

Commands connect to a running Trace server to list agents, view telemetry,
and send response actions to deployed endpoint agents.

Requires --server or TRACE_SERVER_URL env var and --api-key or TRACE_API_KEY.

Subcommands:
  list          List all registered EDR agents
  view          View agent details and status
  events        View recent events from an agent
  dispatch      Send a response action to an agent (kill, quarantine, block, etc.)
  revoke        Remove an agent from the server`,
	}

	cmd.AddCommand(newEDRListCmd())
	cmd.AddCommand(newEDRViewCmd())
	cmd.AddCommand(newEDREventsCmd())
	cmd.AddCommand(newEDRDispatchCmd())
	cmd.AddCommand(newEDRRevokeCmd())

	cmd.PersistentFlags().String("server", "", "Trace server URL (default: http://localhost:8080)")
	cmd.PersistentFlags().String("api-key", "", "API key for server authentication")

	return cmd
}

func getEDRClient(cmd *cobra.Command) (*edrAPIClient, error) {
	serverURL, _ := cmd.Flags().GetString("server")
	if serverURL == "" {
		serverURL = os.Getenv("TRACE_SERVER_URL")
	}
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	apiKey, _ := cmd.Flags().GetString("api-key")
	if apiKey == "" {
		apiKey = os.Getenv("TRACE_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("API key required: set --api-key, TRACE_API_KEY env, or run 'trace init'")
	}

	return &edrAPIClient{
		baseURL: strings.TrimRight(serverURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
	}, nil
}

type edrAPIClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func (c *edrAPIClient) do(method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (HTTP %d): %s", resp.StatusCode, string(data))
	}

	return data, nil
}

func (c *edrAPIClient) listAgents() ([]edrAgentSummary, error) {
	data, err := c.do("GET", "/api/v1/edr/agents", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Agents []edrAgentSummary `json:"agents"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return resp.Agents, nil
}

func (c *edrAPIClient) getAgentEvents(agentID string, limit int) ([]json.RawMessage, error) {
	data, err := c.do("GET", fmt.Sprintf("/api/v1/edr/events?agent_id=%s&limit=%d", agentID, limit), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return resp.Events, nil
}

func (c *edrAPIClient) dispatchAction(agentID, actionType, target string, params map[string]any) (string, error) {
	body := map[string]any{
		"agent_id":    agentID,
		"action_type": actionType,
		"target":      target,
		"params":      params,
		"timeout":     30,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	resp, err := c.do("POST", "/api/v1/edr/actions/dispatch", strings.NewReader(string(data)))
	if err != nil {
		return "", err
	}

	var result struct {
		ActionID string `json:"action_id"`
		Status   string `json:"status"`
	}
	json.Unmarshal(data, &result)

	if err := json.Unmarshal(resp, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	return result.ActionID, nil
}

type edrAgentSummary struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	IP            string `json:"ip"`
	LastHeartbeat string `json:"last_heartbeat"`
	CPUCount      int    `json:"cpu_count"`
	MemoryMB      int64  `json:"memory_mb"`
	CreatedAt     string `json:"created_at"`
}

func newEDRListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all registered EDR agents",
		RunE: func(c *cobra.Command, args []string) error {
			client, err := getEDRClient(c.Parent())
			if err != nil {
				return err
			}
			agents, err := client.listAgents()
			if err != nil {
				return fmt.Errorf("list agents: %w", err)
			}
			if len(agents) == 0 {
				fmt.Println("No EDR agents registered.")
				return nil
			}
			fmt.Printf("\n  %-36s  %-20s  %-10s  %-12s  %-25s\n", "AGENT ID", "HOSTNAME", "PLATFORM", "STATUS", "LAST HEARTBEAT")
			fmt.Println(strings.Repeat("─", 110))
			for _, a := range agents {
				status := a.Status
				lastSeen := a.LastHeartbeat
				if lastSeen == "" {
					lastSeen = "never"
				}
				if len(lastSeen) > 25 {
					lastSeen = lastSeen[:25]
				}
				fmt.Printf("  %-36s  %-20s  %-10s  %-12s  %-25s\n",
					a.ID[:36], a.Hostname, a.Platform+"/"+a.Arch, status, lastSeen)
			}
			fmt.Println()
			return nil
		},
	}
}

func newEDRViewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "view <agent-id>",
		Short: "View agent details and status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getEDRClient(cmd.Parent())
			if err != nil {
				return err
			}

			agents, err := client.listAgents()
			if err != nil {
				return err
			}

			prefix := args[0]
			for _, a := range agents {
				if strings.HasPrefix(a.ID, prefix) || strings.HasPrefix(a.Hostname, prefix) {
					printAgentDetail(&a)
					return nil
				}
			}
			return fmt.Errorf("agent not found: %s", prefix)
		},
	}
}

func printAgentDetail(a *edrAgentSummary) {
	fmt.Printf("\n  Agent ID:     %s\n", a.ID)
	fmt.Printf("  Hostname:     %s\n", a.Hostname)
	fmt.Printf("  Platform:     %s/%s\n", a.Platform, a.Arch)
	fmt.Printf("  Version:      %s\n", a.Version)
	fmt.Printf("  Status:       %s\n", a.Status)
	fmt.Printf("  IP Address:   %s\n", a.IP)
	fmt.Printf("  CPU Count:    %d\n", a.CPUCount)
	fmt.Printf("  Memory:       %d MB\n", a.MemoryMB)
	fmt.Printf("  Last Seen:    %s\n", a.LastHeartbeat)
	fmt.Printf("  Registered:   %s\n", a.CreatedAt)
	fmt.Println()
}

func newEDREventsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "events <agent-id>",
		Short: "View recent events from an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getEDRClient(cmd.Parent())
			if err != nil {
				return err
			}

			events, err := client.getAgentEvents(args[0], 20)
			if err != nil {
				return err
			}

			if len(events) == 0 {
				fmt.Println("No events found.")
				return nil
			}

			fmt.Println()
			for i, raw := range events {
				var evt struct {
					Type      string `json:"event_type"`
					Severity  int    `json:"severity"`
					Timestamp string `json:"timestamp"`
					Data      string `json:"data,omitempty"`
				}
				json.Unmarshal(raw, &evt)

				sev := "INFO"
				if evt.Severity >= 7 {
					sev = "CRIT"
				} else if evt.Severity >= 5 {
					sev = "HIGH"
				} else if evt.Severity >= 3 {
					sev = "WARN"
				}

				ts := evt.Timestamp
				if len(ts) > 19 {
					ts = ts[:19]
				}
				fmt.Printf("  %s  [%s]  %s\n", ts, sev, evt.Type)

				if i >= 50 {
					fmt.Println("  ... (truncated)")
					break
				}
			}
			fmt.Println()
			return nil
		},
	}
}

func newEDRDispatchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dispatch <agent-id> <action> [target]",
		Short: "Send a response action to an agent",
		Long: `Send a response action to an EDR agent.

Actions:
  kill-process    Kill a process by PID or name (target=pid or target=name)
  quarantine      Quarantine a file (target=/path/to/file)
  block-ip        Block an IP address (target=192.168.1.1)
  run-script      Execute a script (target=script content)
  isolate         Isolate host from network (target=hostname)
  collect-forensics  Collect forensic snapshot (target=optional)
  system-snapshot    Take system snapshot (target=optional)`,
		Args: cobra.MinimumNArgs(2),
		Example: `  trace edr dispatch abc123 kill-process --pid 4521
  trace edr dispatch abc123 quarantine --path /tmp/malware.exe
  trace edr dispatch abc123 block-ip --ip 203.0.113.42
  trace edr dispatch abc123 isolate`,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getEDRClient(cmd.Parent())
			if err != nil {
				return err
			}

			agentID := args[0]
			action := args[1]
			target := ""
			if len(args) > 2 {
				target = args[2]
			}

			params := map[string]any{}
			if pid, _ := cmd.Flags().GetInt("pid"); pid > 0 {
				params["pid"] = pid
			}
			if path, _ := cmd.Flags().GetString("path"); path != "" {
				params["path"] = path
				if target == "" {
					target = path
				}
			}
			if ip, _ := cmd.Flags().GetString("ip"); ip != "" {
				params["ip"] = ip
				if target == "" {
					target = ip
				}
			}
			if script, _ := cmd.Flags().GetString("script"); script != "" {
				params["script"] = script
			}

			actionID, err := client.dispatchAction(agentID, action, target, params)
			if err != nil {
				return fmt.Errorf("dispatch failed: %w", err)
			}

			fmt.Printf("\n  Action dispatched: %s\n", actionID)
			fmt.Printf("  Agent: %s\n", agentID)
			fmt.Printf("  Type:  %s\n", action)
			if target != "" {
				fmt.Printf("  Target: %s\n", target)
			}
			fmt.Printf("\n  Use 'trace edr events %s' to see results.\n", agentID)
			return nil
		},
	}
}

func newEDRRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <agent-id>",
		Short: "Revoke and remove an agent from the server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := getEDRClient(cmd.Parent())
			if err != nil {
				return err
			}

			resp, err := client.do("DELETE", fmt.Sprintf("/api/v1/edr/agents/%s", args[0]), nil)
			if err != nil {
				return err
			}

			var result struct {
				Status string `json:"status"`
			}
			json.Unmarshal(resp, &result)
			fmt.Printf("\n  Agent %s: %s\n", args[0], result.Status)
			return nil
		},
	}
}


