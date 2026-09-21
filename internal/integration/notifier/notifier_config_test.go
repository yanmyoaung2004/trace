package notifier

import (
	"context"
	"strings"
	"testing"

	"github.com/yanmyoaung2004/trace/internal/agent"
)
// supplied via LLM input is rejected, never merged over central config.
func TestSecretsRejectedFromInput(t *testing.T) {
	a := NewWithConfig(AgentConfig{
		SlackWebhookURL:     "https://hooks.slack.com/x",
		DiscordWebhookURL:    "https://discord.com/x",
		TelegramBotToken:     "tok",
		TelegramChatID:       "1",
		SMTPHost:            "smtp.example.com",
		SMTPPort:            587,
		SMTPUser:            "u",
		SMTPPassword:        "p",
		PagerDutyRoutingKey: "pd",
	})

	cases := []struct {
		name  string
		input agent.Input
	}{
		{"slack", agent.Input{"action": "slack", "message": "m", "webhook_url": "https://evil.example/"}},
		{"discord", agent.Input{"action": "discord", "message": "m", "webhook_url": "https://evil.example/"}},
		{"telegram", agent.Input{"action": "telegram", "message": "m", "bot_token": "evil"}},
		{"email", agent.Input{"action": "email", "to": "a@b.c", "smtp_password": "evil"}},
		{"pagerduty", agent.Input{"action": "pagerduty", "summary": "s", "routing_key": "evil"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := a.Execute(context.Background(), tc.input)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range out {
				if s, ok := v.(string); ok && strings.Contains(s, "evil") {
					t.Fatalf("evil secret leaked into output: %v", out)
				}
			}
			if st, _ := out["status"].(string); st != "error" {
				t.Errorf("expected error status for secret input, got %v", out)
			}
		})
	}
}
