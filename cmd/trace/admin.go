package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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
			body := fmt.Sprintf(`{"name":"%s"}`, args[0])
			resp, err := client.Post(client.baseURL+"/api/v1/admin/orgs", "application/json", bytes.NewReader([]byte(body)))
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
			resp, err := client.Get(client.baseURL + "/api/v1/admin/orgs")
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				Orgs []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"orgs"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
			resp, err := client.Get(client.baseURL + "/api/v1/admin/users")
			if err != nil {
				return fmt.Errorf("request: %w", err)
			}
			defer resp.Body.Close()
			var result struct {
				Users []struct {
					ID    string `json:"id"`
					Email string `json:"email"`
					Role  string `json:"role"`
					OrgID string `json:"org_id"`
				} `json:"users"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("parse: %w", err)
			}
			fmt.Printf("New API key for %s:\n  %s\n", args[0], result.APIKey)
			return nil
		},
	}

	cmd.AddCommand(orgCmd, userCmd, keyCmd)

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
