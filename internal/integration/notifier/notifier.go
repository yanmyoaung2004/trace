package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/innoigniter/edge/internal/agent"
)

type Agent struct {
	httpClient *http.Client
}

func New() *Agent {
	return &Agent{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (a *Agent) Name() string { return "notifier" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "slack", Inputs: []string{"webhook_url", "message", "title"}, Outputs: []string{"status"}},
		{Action: "discord", Inputs: []string{"webhook_url", "message", "title"}, Outputs: []string{"status"}},
	}
}

type slackPayload struct {
	Text        string `json:"text"`
	Username    string `json:"username,omitempty"`
	IconEmoji   string `json:"icon_emoji,omitempty"`
}

type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
}

type discordPayload struct {
	Content string         `json:"content"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

func (a *Agent) Execute(ctx context.Context, input agent.Input) (agent.Output, error) {
	action, _ := input["action"].(string)
	switch action {
	case "slack":
		return a.sendSlack(ctx, input)
	case "discord":
		return a.sendDiscord(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) sendSlack(ctx context.Context, input agent.Input) (agent.Output, error) {
	webhookURL, _ := input["webhook_url"].(string)
	message, _ := input["message"].(string)
	title, _ := input["title"].(string)

	if webhookURL == "" {
		return agent.Output{"status": "error", "error": "webhook_url is required"}, nil
	}
	if message == "" && title == "" {
		return agent.Output{"status": "error", "error": "message or title is required"}, nil
	}

	text := title
	if text != "" && message != "" {
		text = fmt.Sprintf("*%s*\n%s", title, message)
	} else if message != "" {
		text = message
	}

	payload := slackPayload{
		Text:      text,
		Username:  "InnoIgniterAI",
		IconEmoji: ":shield:",
	}

	return a.postWebhook(ctx, webhookURL, payload)
}

func (a *Agent) sendDiscord(ctx context.Context, input agent.Input) (agent.Output, error) {
	webhookURL, _ := input["webhook_url"].(string)
	message, _ := input["message"].(string)
	title, _ := input["title"].(string)

	if webhookURL == "" {
		return agent.Output{"status": "error", "error": "webhook_url is required"}, nil
	}

	payload := discordPayload{}
	if title != "" {
		payload.Embeds = []discordEmbed{{
			Title:       title,
			Description: message,
			Color:       0x58a6ff,
		}}
	} else {
		payload.Content = message
	}

	return a.postWebhook(ctx, webhookURL, payload)
}

func (a *Agent) postWebhook(ctx context.Context, url string, payload any) (agent.Output, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return agent.Output{"status": "error", "error": err.Error()}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return agent.Output{"status": "error", "error": err.Error()}, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return agent.Output{"status": "error", "error": err.Error()}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return agent.Output{"status": "error", "error": fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}

	return agent.Output{"status": "sent", "provider": url, "http_status": resp.StatusCode}, nil
}
