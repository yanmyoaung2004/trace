package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/yanmyoaung2004/trace/internal/investigation"
)

type SyncClient struct {
	serverAddr string
	httpClient *http.Client
	nodeID     string
	hostname   string
	version    string
	invManager *investigation.Manager
	done       chan struct{}
}

func NewSyncClient(addr string, invMgr *investigation.Manager) *SyncClient {
	hostname, _ := os.Hostname()
	return &SyncClient{
		serverAddr: addr,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		hostname:   hostname,
		version:    "0.1.0-dev",
		invManager: invMgr,
		done:       make(chan struct{}),
	}
}

func (c *SyncClient) Register(ctx context.Context) error {
	body := map[string]string{
		"hostname": c.hostname,
		"version":  c.version,
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.postJSON(ctx, "/api/v1/register", body, &resp); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	c.nodeID = resp.ID
	log.Printf("[edge-sync] registered as node %s", c.nodeID[:12])
	return nil
}

func (c *SyncClient) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)

	go func() {
		for {
			select {
			case <-ctx.Done():
				close(c.done)
				return
			case <-ticker.C:
				if err := c.doHeartbeat(ctx); err != nil {
					log.Printf("[edge-sync] heartbeat: %v", err)
				}
				if err := c.syncInvestigations(ctx); err != nil {
					log.Printf("[edge-sync] sync: %v", err)
				}
			}
		}
	}()

	c.syncInvestigations(ctx)
}

func (c *SyncClient) doHeartbeat(ctx context.Context) error {
	return c.postJSON(ctx, "/api/v1/heartbeat", map[string]string{
		"node_id": c.nodeID,
	}, nil)
}

func (c *SyncClient) syncInvestigations(ctx context.Context) error {
	invs, err := c.invManager.ListRecent(ctx, 50)
	if err != nil {
		return err
	}

	for _, inv := range invs {
		indicators := extractIndicators(inv.Intent)
		var confidence *float64
		if inv.Confidence != nil {
			confidence = inv.Confidence
		}

		payload := map[string]any{
			"node_id": c.nodeID,
			"investigation": map[string]any{
				"id":         inv.ID,
				"status":     inv.Status,
				"intent":     inv.Intent,
				"playbook":   inv.Playbook,
				"confidence": confidence,
				"summary":    generateSummary(inv),
				"indicators": indicators,
			},
		}

		if err := c.postJSON(ctx, "/api/v1/push", payload, nil); err != nil {
			log.Printf("[edge-sync] push %s: %v", inv.ID[:12], err)
		}
	}
	return nil
}

func (c *SyncClient) Close() {}

func (c *SyncClient) postJSON(ctx context.Context, path string, req, resp any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverAddr+path, &buf)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(httpResp.Body).Decode(&errResp)
		if errResp.Error != "" {
			return fmt.Errorf("server: %s", errResp.Error)
		}
		return fmt.Errorf("HTTP %d", httpResp.StatusCode)
	}

	if resp != nil {
		return json.NewDecoder(httpResp.Body).Decode(resp)
	}
	return nil
}

func extractIndicators(intent string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(intent); i++ {
		if i == len(intent) || intent[i] == ' ' {
			if i > start {
				f := stringsTrim(intent[start:i])
				if len(f) == 64 || len(f) == 40 || len(f) == 32 {
					out = append(out, f)
				}
			}
			start = i + 1
		}
	}
	return out
}

func stringsTrim(s string) string {
	for len(s) > 0 && !isAlphaNum(s[0]) {
		s = s[1:]
	}
	for len(s) > 0 && !isAlphaNum(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return s
}

func isAlphaNum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func generateSummary(inv investigation.Investigation) string {
	return fmt.Sprintf("Investigation %s: %s [%s]", inv.ID[:12], inv.Intent, inv.Status)
}
