package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func newAdminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrative commands (org and user management)",
		Long:  `Manage organizations and users. Requires admin API key.`,
	}

	orgCmd := &cobra.Command{
		Use:   "org",
		Short: "Manage organizations",
	}

	createOrgCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new organization",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getAdminHTTPClient(cmd)
			body, _ := json.Marshal(map[string]string{"name": args[0]})
			resp, err := client.Post(client.baseURL+"/api/v1/admin/orgs", "application/json", bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("create: %w", err)
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			fmt.Printf("Organization created:\n  ID:   %s\n  Name: %s\n", result.ID, result.Name)
			return nil
		},
	}

	listOrgCmd := &cobra.Command{
		Use:   "list",
		Short: "List organizations",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getAdminHTTPClient(cmd)
			var result struct {
				Orgs []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"orgs"`
			}
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("list: %w", err)
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			if len(result.Orgs) == 0 {
				fmt.Println("No organizations found.")
				return nil
			}
			fmt.Println("\n  Organizations:")
			for _, o := range result.Orgs {
				fmt.Printf("  %s  %s\n", o.ID, o.Name)
			}
			return nil
		},
	}

	orgCmd.AddCommand(createOrgCmd, listOrgCmd)

	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
	}

	createUserCmd := &cobra.Command{
		Use:   "create <email>",
		Short: "Create a new user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")
			if role == "" {
				role = "analyst"
			}
			orgID, _ := cmd.Flags().GetString("org")
			apiKey, _ := cmd.Flags().GetString("api-key-override")

			bodyMap := map[string]string{"email": args[0], "role": role}
			if orgID != "" {
				bodyMap["org_id"] = orgID
			}
			if apiKey != "" {
				bodyMap["api_key"] = apiKey
			}
			bodyBytes, _ := json.Marshal(bodyMap)

			client := getAdminHTTPClient(cmd)
			resp, err := client.Post(client.baseURL+"/api/v1/admin/users", "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				ID     string `json:"id"`
				APIKey string `json:"api_key"`
				Role   string `json:"role"`
				OrgID  string `json:"org_id"`
			}
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("create: %w", err)
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			fmt.Printf("User created:\n  ID:     %s\n  Role:   %s\n  API Key: %s\n", result.ID, result.Role, result.APIKey)
			if result.OrgID != "" {
				fmt.Printf("  Org:    %s\n", result.OrgID)
			}
			return nil
		},
	}
	createUserCmd.Flags().String("role", "analyst", "User role (admin, analyst)")
	createUserCmd.Flags().String("org", "", "Organization ID")
	createUserCmd.Flags().String("api-key-override", "", "Override auto-generated API key")

	listUserCmd := &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getAdminHTTPClient(cmd)
			var result struct {
				Users []struct {
					ID    string `json:"id"`
					Email string `json:"email"`
					Role  string `json:"role"`
					OrgID string `json:"org_id"`
				} `json:"users"`
			}
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("list: %w", err)
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			if len(result.Users) == 0 {
				fmt.Println("No users found.")
				return nil
			}
			fmt.Println("\n  Users:")
			for _, u := range result.Users {
				org := u.OrgID
				if org == "" {
					org = "(none)"
				}
				fmt.Printf("  %s  %-30s  %-10s  org: %s\n", u.ID, u.Email, u.Role, org)
			}
			return nil
		},
	}

	userCmd.AddCommand(createUserCmd, listUserCmd)

	tokenCmd := &cobra.Command{
		Use:   "token",
		Short: "Manage enrollment provision tokens",
	}

	mintTokenCmd := &cobra.Command{
		Use:   "mint <org-id>",
		Short: "Mint a single-use enrollment token for an org",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			label, _ := cmd.Flags().GetString("label")
			ttl, _ := cmd.Flags().GetInt("ttl-hours")
			body, _ := json.Marshal(map[string]any{"org_id": args[0], "label": label, "ttl_hours": ttl})
			client := getAdminHTTPClient(cmd)
			resp, err := client.Post(client.baseURL+"/api/v1/admin/provision-tokens", "application/json", bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				ProvisionToken string `json:"provision_token"`
				OrgID          string `json:"org_id"`
			}
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("mint: %w", err)
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			fmt.Printf("Provision token (single-use, show once):\n  %s\n  Org: %s\n", result.ProvisionToken, result.OrgID)
			return nil
		},
	}
	mintTokenCmd.Flags().String("label", "", "Token label")
	mintTokenCmd.Flags().Int("ttl-hours", 24, "Token lifetime in hours")

	listTokenCmd := &cobra.Command{
		Use:   "list",
		Short: "List provision tokens (metadata only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			orgID, _ := cmd.Flags().GetString("org")
			client := getAdminHTTPClient(cmd)
			path := "/api/v1/admin/provision-tokens"
			if orgID != "" {
				path += "?org_id=" + url.QueryEscape(orgID)
			}
			resp, err := client.Get(client.baseURL + path)
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("list: %w", err)
			}
			var result struct {
				Tokens []map[string]any `json:"tokens"`
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			if len(result.Tokens) == 0 {
				fmt.Println("No provision tokens found.")
				return nil
			}
			fmt.Println("\n  Provision tokens:")
			for _, t := range result.Tokens {
				fmt.Printf("  %v  org=%v  label=%v  expires=%v  used=%v\n",
					t["prefix"], t["org_id"], t["label"], t["expires_at"], t["used_at"])
			}
			return nil
		},
	}
	listTokenCmd.Flags().String("org", "", "Filter by organization ID")

	tokenCmd.AddCommand(mintTokenCmd, listTokenCmd)

	keyCmd := &cobra.Command{
		Use:   "rotate-key <email>",
		Short: "Rotate API key for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getAdminHTTPClient(cmd)
			resp, err := client.Post(client.baseURL+"/api/v1/admin/users/"+args[0]+"/rotate-key", "application/json", nil)
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				APIKey string `json:"api_key"`
			}
			raw, _ := io.ReadAll(resp.Body)
			payload, err := unwrapAdminEnvelope(raw)
			if err != nil {
				return fmt.Errorf("rotate: %w", err)
			}
			if err := json.Unmarshal(payload, &result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			fmt.Printf("New API key for %s:\n  %s\n", args[0], result.APIKey)
			return nil
		},
	}

	cmd.AddCommand(orgCmd, userCmd, tokenCmd, keyCmd)

	return cmd
}

type adminClient struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func getAdminHTTPClient(cmd *cobra.Command) *adminClient {
	baseURL := getServerURL(cmd, "")
	apiKey := getAPIKey(cmd)
	return &adminClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *adminClient) Get(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	return c.client.Do(req)
}

func (c *adminClient) Post(url, contentType string, body *bytes.Reader) (*http.Response, error) {
	req, _ := http.NewRequest("POST", url, body)
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.client.Do(req)
}

func getServerURL(cmd *cobra.Command, defaultURL string) string {
	if defaultURL == "" {
		defaultURL = "http://localhost:8080"
	}
	if serverURL, _ := cmd.Flags().GetString("server"); serverURL != "" {
		return serverURL
	}
	if v := os.Getenv("TRACE_SERVER_URL"); v != "" {
		return v
	}
	return defaultURL
}

func getAPIKey(cmd *cobra.Command) string {
	if key, _ := cmd.Flags().GetString("api-key"); key != "" {
		return key
	}
	if v := os.Getenv("TRACE_API_KEY"); v != "" {
		return v
	}
	return ""
}

// unwrapAdminEnvelope extracts data from the standard {data,error,code}
// envelope, tolerating pre-envelope bare payloads during rollout.
func unwrapAdminEnvelope(raw []byte) ([]byte, error) {
	var env struct {
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
		Code  int             `json:"code"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if len(env.Data) == 0 && env.Error == "" && env.Code == 0 {
		return raw, nil
	}
	if env.Error != "" {
		return nil, fmt.Errorf("server: %s", env.Error)
	}
	if len(env.Data) == 0 {
		return []byte("null"), nil
	}
	return env.Data, nil
}
