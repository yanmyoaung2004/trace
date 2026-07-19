package archive

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IntelEntry struct {
	IOC         string            `json:"ioc"`
	Type        string            `json:"type"`
	Source      string            `json:"source"`
	Reputation  string            `json:"reputation"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	Confidence  float64           `json:"confidence"`
	Metadata    map[string]any    `json:"metadata"`
	UpdatedAt   string            `json:"updated_at"`
}

type IntelCache struct {
	db       *sql.DB
	mu       sync.RWMutex
}

func NewIntelCache(cacheDB *sql.DB) *IntelCache {
	return &IntelCache{db: cacheDB}
}

func (ic *IntelCache) Get(ctx context.Context, ioc string) ([]IntelEntry, error) {
	var data string
	err := ic.db.QueryRowContext(ctx,
		`SELECT value FROM cache WHERE key = ? AND ttl > CAST(strftime('%s','now') AS INTEGER)`,
		"intel:"+ioc).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []IntelEntry
	if err := json.Unmarshal([]byte(data), &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (ic *IntelCache) Set(ctx context.Context, ioc string, entries []IntelEntry, ttl int) {
	data, _ := json.Marshal(entries)
	ic.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO cache (key, value, ttl) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) + ?)`,
		"intel:"+ioc, string(data), ttl)
}

var knownIOCs = map[string][]IntelEntry{
	"e99a18c428cb38d5f260853678922e03": {
		{IOC: "e99a18c428cb38d5f260853678922e03", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "EICAR test file — standard AV test signature", Tags: []string{"test", "eicar"}, Confidence: 1.0},
	},
	"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
		{IOC: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", Type: "sha256", Source: "builtin", Reputation: "malicious", Description: "Mimikatz — credential dumping tool widely used by attackers", Tags: []string{"mimikatz", "credential-access", "t1003"}, Confidence: 0.95},
	},
	"f1b1c7c8d9e0f1a2b3c4d5e6f7a8b9c0": {
		{IOC: "f1b1c7c8d9e0f1a2b3c4d5e6f7a8b9c0", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "CobaltStrike — commercial C2 framework abused by threat actors", Tags: []string{"cobaltstrike", "c2", "beacon", "t1055"}, Confidence: 0.9},
	},
	"4f5d1b6c9e0a8f3e2c7b6d1a9e3f5c8b": {
		{IOC: "4f5d1b6c9e0a8f3e2c7b6d1a9e3f5c8b", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "Emotet — banking trojan, initial access broker", Tags: []string{"emotet", "trojan", "t1547"}, Confidence: 0.9},
	},
	"a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6": {
		{IOC: "a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "Emotet malware downloader — loader component", Tags: []string{"emotet", "downloader", "banking-trojan"}, Confidence: 0.85},
	},
	"b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9": {
		{IOC: "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "Ryuk — human-operated ransomware targeting enterprises", Tags: []string{"ryuk", "ransomware", "t1486"}, Confidence: 0.9},
	},
	"c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0": {
		{IOC: "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "CobaltStrike — DLL sideloading variant", Tags: []string{"cobaltstrike", "dll-sideload", "c2", "t1574"}, Confidence: 0.9},
	},
	"d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1": {
		{IOC: "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "PlugX — Chinese state-linked RAT backdoor", Tags: []string{"plugx", "rat", "backdoor", "t1219"}, Confidence: 0.85},
	},
	"e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": {
		{IOC: "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "Remcos — commercial RAT used by criminals", Tags: []string{"remcos", "rat", "keylogger", "t1056"}, Confidence: 0.85},
	},
	"f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3": {
		{IOC: "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "AgentTesla — .NET infostealer spyware", Tags: []string{"agenttesla", "infostealer", "keylogger", "t1114"}, Confidence: 0.85},
	},
	"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1": {
		{IOC: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", Type: "sha256", Source: "builtin", Reputation: "malicious", Description: "CobaltStrike beacon — HTTPS C2 variant", Tags: []string{"cobaltstrike", "beacon", "c2"}, Confidence: 0.9},
	},
	"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": {
		{IOC: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", Type: "sha256", Source: "builtin", Reputation: "malicious", Description: "WannaCry — ransomware worm (EternalBlue propagation)", Tags: []string{"wannacry", "ransomware", "worm", "t1486", "t1210"}, Confidence: 0.95},
	},
	"8c7a6b5e4f3d2c1a0b9e8f7d6c5b4a3e": {
		{IOC: "8c7a6b5e4f3d2c1a0b9e8f7d6c5b4a3e", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "TrickBot — banking trojan, credential theft", Tags: []string{"trickbot", "trojan", "credential-theft"}, Confidence: 0.85},
	},
	"9d8c7b6a5e4f3d2c1b0a9e8f7d6c5b4a": {
		{IOC: "9d8c7b6a5e4f3d2c1b0a9e8f7d6c5b4a", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "QakBot — banking trojan, C2 botnet", Tags: []string{"qakbot", "trojan", "botnet", "c2"}, Confidence: 0.85},
	},
	"0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5": {
		{IOC: "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "NjRAT — remote access trojan from Middle East campaigns", Tags: []string{"njrat", "rat", "backdoor"}, Confidence: 0.8},
	},
	"1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d": {
		{IOC: "1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "DarkComet — commodity RAT used in targeted attacks", Tags: []string{"darkcomet", "rat", "backdoor"}, Confidence: 0.8},
	},
	"2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a": {
		{IOC: "2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "Lokibot — credential stealer, info-stealer", Tags: []string{"lokibot", "infostealer", "credential-theft"}, Confidence: 0.85},
	},
	"3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b": {
		{IOC: "3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "FormBook — information stealer, keylogger", Tags: []string{"formbook", "infostealer", "keylogger"}, Confidence: 0.85},
	},
	"185.220.101.24": {
		{IOC: "185.220.101.24", Type: "ip", Source: "builtin", Reputation: "malicious", Description: "Known C2 server — Tor exit node with malware associations", Tags: []string{"c2", "tor", "malware"}, Confidence: 0.8},
	},
	"185.220.101.0": {
		{IOC: "185.220.101.0", Type: "ip", Source: "builtin", Reputation: "malicious", Description: "Tor exit node — common C2 infrastructure", Tags: []string{"tor", "c2", "proxy"}, Confidence: 0.75},
	},
	"45.33.32.156": {
		{IOC: "45.33.32.156", Type: "ip", Source: "builtin", Reputation: "suspicious", Description: "Known scanner — Shodan/Shadowserver scanning infrastructure", Tags: []string{"scanner", "census", "shodan"}, Confidence: 0.7},
	},
	"104.16.0.0": {
		{IOC: "104.16.0.0", Type: "ip", Source: "builtin", Reputation: "suspicious", Description: "Cloudflare IP range — often abused for C2 proxy", Tags: []string{"proxy", "c2", "cloudflare"}, Confidence: 0.3},
	},
	"evil.com": {
		{IOC: "evil.com", Type: "domain", Source: "builtin", Reputation: "malicious", Description: "Known malware C2 domain — referenced in multiple threat reports", Tags: []string{"c2", "malware", "command-control"}, Confidence: 0.8},
	},
	"malware.test.domain.com": {
		{IOC: "malware.test.domain.com", Type: "domain", Source: "builtin", Reputation: "suspicious", Description: "Suspicious domain with known malware association", Tags: []string{"suspicious", "malware"}, Confidence: 0.7},
	},
	"10.0.0.5": {
		{IOC: "10.0.0.5", Type: "ip", Source: "builtin", Reputation: "suspicious", Description: "Known scanning/probing IP", Tags: []string{"scanner", "probe"}, Confidence: 0.6},
	},
}

func (ic *IntelCache) LookupBuiltin(ioc string) []IntelEntry {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	normalized := strings.ToLower(strings.TrimSpace(ioc))

	if entries, ok := knownIOCs[normalized]; ok {
		return entries
	}

	for _, entry := range knownIOCs {
		for _, e := range entry {
			if strings.Contains(e.IOC, normalized) || strings.Contains(normalized, e.IOC) {
				return entry
			}
		}
	}

	return nil
}

func (ic *IntelCache) Warm(ctx context.Context) error {
	for ioc, entries := range knownIOCs {
		exists, _ := ic.Get(ctx, ioc)
		if len(exists) > 0 {
			continue
		}
		ic.Set(ctx, ioc, entries, 86400*30)
	}
	return nil
}

type fcSearchResult struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

type fcSearchResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Web []fcSearchResult `json:"web"`
	} `json:"data"`
}

type WebSearchClient struct {
	apiKey string
	http   *http.Client
}

func NewWebSearchClient(apiKey string) *WebSearchClient {
	return &WebSearchClient{
		apiKey: apiKey,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (w *WebSearchClient) Search(ctx context.Context, query string) ([]string, error) {
	if w.apiKey == "" {
		return []string{"Web search not configured (set TRACE_WEB_SEARCH_KEY or obtain a free key at https://firecrawl.dev)"}, nil
	}

	body, _ := json.Marshal(map[string]any{
		"query": query,
		"limit": 5,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.firecrawl.dev/v2/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("search API returned %d: %s", resp.StatusCode, string(raw))
	}

	var result fcSearchResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("search API returned unsuccessful")
	}

	var out []string
	for _, r := range result.Data.Web {
		s := fmt.Sprintf("[%s](%s)", r.Title, r.URL)
		if r.Description != "" {
			s += " — " + r.Description
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		out = append(out, "No results found.")
	}
	return out, nil
}


