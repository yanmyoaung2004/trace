package notifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"time"

	"github.com/yanmyoaung2004/trace/internal/agent"
)

type Agent struct {
	httpClient          *http.Client
	SlackWebhookURL     string
	DiscordWebhookURL    string
	TelegramBotToken     string
	TelegramChatID       string
	TelegramAPIBase     string   // for testing; default https://api.telegram.org
	PagerDutyAPIBase    string   // for testing; default https://events.pagerduty.com
	SMTPHost            string
	SMTPPort            int
	SMTPUser            string
	SMTPPassword        string
	SMTPFrom            string
	EmailTo             string
	PagerDutyRoutingKey string
	WebhookURL          string
}

func New() *Agent {
	return &Agent{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// NewWithConfig wires config-supplied credentials; input params can never
// override secrets (secret inputs are rejected, not merged). Non-secret
// routing (which channel config to use, message text) still comes from input.
func NewWithConfig(cfg AgentConfig) *Agent {
	return &Agent{
		httpClient:          &http.Client{Timeout: 15 * time.Second},
		SlackWebhookURL:     cfg.SlackWebhookURL,
		DiscordWebhookURL:    cfg.DiscordWebhookURL,
		TelegramBotToken:     cfg.TelegramBotToken,
		TelegramChatID:       cfg.TelegramChatID,
		SMTPHost:            cfg.SMTPHost,
		SMTPPort:            cfg.SMTPPort,
		SMTPUser:            cfg.SMTPUser,
		SMTPPassword:        cfg.SMTPPassword,
		SMTPFrom:            cfg.SMTPFrom,
		EmailTo:             cfg.EmailTo,
		PagerDutyRoutingKey: cfg.PagerDutyRoutingKey,
		WebhookURL:          cfg.WebhookURL,
	}
}

type AgentConfig struct {
	SlackWebhookURL     string `json:"slack_webhook_url"`
	DiscordWebhookURL    string `json:"discord_webhook_url"`
	TelegramBotToken     string `json:"telegram_bot_token"`
	TelegramChatID       string `json:"telegram_chat_id"`
	SMTPHost            string `json:"smtp_host"`
	SMTPPort            int    `json:"smtp_port"`
	SMTPUser            string `json:"smtp_user"`
	SMTPPassword        string `json:"smtp_password"`
	SMTPFrom            string `json:"smtp_from"`
	EmailTo             string `json:"email_to"`
	PagerDutyRoutingKey string `json:"pagerduty_routing_key"`
	WebhookURL          string `json:"webhook_url"`
}

// secretInputKeys are rejected from LLM input on every channel: webhooks,
// tokens, routing keys, and SMTP credentials are config-wired at
// construction. Message text and routing labels stay input-supplied.
// Exception: the generic `webhook` action's per-call `url` stays
// input-supplied — it is an arbitrary per-alert destination, not a stored
// credential (the config WebhookURL is only a default).
var secretInputKeys = map[string]bool{
	"webhook_url": true, "bot_token": true, "routing_key": true,
	"smtp_host": true, "smtp_port": true, "smtp_user": true,
	"smtp_password": true,
}

// rejectSecretInputs refuses secrets smuggled in via LLM input params.
func rejectSecretInputs(input agent.Input) *agent.Output {
	for k := range secretInputKeys {
		if _, ok := input[k]; ok {
			return &agent.Output{"status": "error", "error": "secret '" + k + "' must come from central config (NewWithConfig), not input params"}
		}
	}
	return nil
}
func (a *Agent) Name() string { return "notifier" }

func (a *Agent) Capabilities() []agent.Capability {
	return []agent.Capability{
		{Action: "slack", Inputs: []string{"message", "title"}, Outputs: []string{"status"}},
		{Action: "discord", Inputs: []string{"message", "title"}, Outputs: []string{"status"}},
		{Action: "telegram", Inputs: []string{"message"}, Outputs: []string{"status"}},
		{Action: "email", Inputs: []string{"to", "subject", "body"}, Outputs: []string{"status"}},
		{Action: "pagerduty", Inputs: []string{"summary", "severity"}, Outputs: []string{"status"}},
		{Action: "webhook", Inputs: []string{"url", "method", "body"}, Outputs: []string{"status"}},
	}
}

type slackPayload struct {
	Text      string `json:"text"`
	Username  string `json:"username,omitempty"`
	IconEmoji string `json:"icon_emoji,omitempty"`
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
	case "telegram":
		return a.sendTelegram(ctx, input)
	case "email":
		return a.sendEmail(ctx, input)
	case "pagerduty":
		return a.sendPagerDuty(ctx, input)
	case "webhook":
		return a.sendWebhook(ctx, input)
	default:
		return nil, fmt.Errorf("unknown action: %s", action)
	}
}

func (a *Agent) sendSlack(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	webhookURL := a.SlackWebhookURL
	message, _ := input["message"].(string)
	title, _ := input["title"].(string)

	if webhookURL == "" {
		return agent.Output{"status": "error", "error": "webhook_url is required (central config)"}, nil
	}
	if !isHTTPURL(webhookURL) {
		return agent.Output{"status": "error", "error": "invalid webhook URL"}, nil
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
		Username:  "Trace",
		IconEmoji: ":shield:",
	}

	return a.postWebhook(ctx, webhookURL, payload)
}

func (a *Agent) sendDiscord(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	webhookURL := a.DiscordWebhookURL
	message, _ := input["message"].(string)
	title, _ := input["title"].(string)

	if webhookURL == "" {
		return agent.Output{"status": "error", "error": "webhook_url is required (central config)"}, nil
	}
	if !isHTTPURL(webhookURL) {
		return agent.Output{"status": "error", "error": "invalid webhook URL"}, nil
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

	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := a.httpClient.Do(req)
		if err != nil {
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
				continue
			}
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			return agent.Output{"status": "error", "error": "rate limited after retries"}, nil
		}

		if resp.StatusCode >= 500 {
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
				continue
			}
			return agent.Output{"status": "error", "error": fmt.Sprintf("HTTP %d after retries", resp.StatusCode)}, nil
		}

		if resp.StatusCode >= 400 {
			return agent.Output{"status": "error", "error": fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
		}

		return agent.Output{"status": "sent", "provider": url, "http_status": resp.StatusCode}, nil
	}

	return agent.Output{"status": "error", "error": "max retries exceeded"}, nil
}

func (a *Agent) sendTelegram(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	botToken := a.TelegramBotToken
	chatID := a.TelegramChatID
	message, _ := input["message"].(string)

	if botToken == "" || chatID == "" || message == "" {
		return agent.Output{"status": "error", "error": "bot_token, chat_id, and message are required (token/chat from central config)"}, nil
	}

	base := a.TelegramAPIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", base, botToken)
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "HTML",
		"disable_web_page_preview": true,
	}

	return a.postWebhook(ctx, url, payload)
}

func (a *Agent) sendEmail(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	to, _ := input["to"].(string)
	if to == "" {
		to = a.EmailTo
	}
	subject, _ := input["subject"].(string)
	body, _ := input["body"].(string)
	host := a.SMTPHost
	port := a.SMTPPort
	user := a.SMTPUser
	pass := a.SMTPPassword
	from, _ := input["from"].(string)
	if from == "" {
		from = a.SMTPFrom
	}

	if host == "" || port == 0 || to == "" {
		return agent.Output{"status": "error", "error": "smtp_host, smtp_port, and to are required (smtp from central config)"}, nil
	}


	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n%s",
		from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", host, port)

	// Port 465 = SMTPS (direct SSL), all others use STARTTLS
	if port == 465 {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
		if err != nil {
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			conn.Close()
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		defer client.Close()
		if user != "" {
			auth := smtp.PlainAuth("", user, pass, host)
			if err := client.Auth(auth); err != nil {
				return agent.Output{"status": "error", "error": err.Error()}, nil
			}
		}
		if err := client.Mail(from); err != nil {
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		if err := client.Rcpt(to); err != nil {
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		w, err := client.Data()
		if err != nil {
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
		w.Write([]byte(msg))
		w.Close()
	} else {
		auth := smtp.PlainAuth("", user, pass, host)
		if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg)); err != nil {
			return agent.Output{"status": "error", "error": err.Error()}, nil
		}
	}

	return agent.Output{"status": "sent", "channel": "email", "to": to}, nil
}

func (a *Agent) sendPagerDuty(ctx context.Context, input agent.Input) (agent.Output, error) {
	if rej := rejectSecretInputs(input); rej != nil {
		return *rej, nil
	}
	routingKey := a.PagerDutyRoutingKey
	summary, _ := input["summary"].(string)
	sev, _ := input["severity"].(string)
	if sev == "" {
		sev = "warning"
	}
	source, _ := input["source"].(string)
	if source == "" {
		source = "trace"
	}

	if routingKey == "" || summary == "" {
		return agent.Output{"status": "error", "error": "routing_key and summary are required (routing_key from central config)"}, nil
	}


	dedupHash := sha256.Sum256([]byte(summary + source))
	payload := map[string]any{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"dedup_key":    "trace-" + hex.EncodeToString(dedupHash[:16]),
		"payload": map[string]any{
			"summary":  summary,
			"severity": sev,
			"source":   source,
		},
	}

	pdBase := a.PagerDutyAPIBase
	if pdBase == "" {
		pdBase = "https://events.pagerduty.com"
	}
	return a.postWebhook(ctx, pdBase+"/v2/enqueue", payload)
}

func (a *Agent) sendWebhook(ctx context.Context, input agent.Input) (agent.Output, error) {
	url, _ := input["url"].(string)
	if url == "" {
		url = a.WebhookURL
	}
	method, _ := input["method"].(string)
	if method == "" {
		method = "POST"
	}
	body, _ := input["body"].(string)

	if url == "" {
		return agent.Output{"status": "error", "error": "url is required"}, nil
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		return agent.Output{"status": "error", "error": err.Error()}, nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return agent.Output{"status": "error", "error": err.Error()}, nil
	}
	defer resp.Body.Close()

	return agent.Output{"status": "sent", "provider": "webhook", "http_status": resp.StatusCode}, nil
}

func isHTTPURL(s string) bool {
	return (len(s) > 7 && s[:7] == "http://") || (len(s) > 8 && s[:8] == "https://")
}
