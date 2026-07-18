package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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
		{IOC: "e99a18c428cb38d5f260853678922e03", Type: "md5", Source: "builtin", Reputation: "malicious", Description: "Known malware sample (EICAR test)", Tags: []string{"test", "eicar"}, Confidence: 1.0},
	},
	"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
		{IOC: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", Type: "sha256", Source: "builtin", Reputation: "malicious", Description: "Mimikatz binary hash", Tags: []string{"mimikatz", "credential-access"}, Confidence: 0.95},
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

type WebSearchClient struct {
	apiKey string
}

func NewWebSearchClient(apiKey string) *WebSearchClient {
	return &WebSearchClient{apiKey: apiKey}
}

func (w *WebSearchClient) Search(ctx context.Context, query string) ([]string, error) {
	if w.apiKey == "" {
		return []string{"Web search not configured (set INNO_WEB_SEARCH_KEY)"}, nil
	}
	return []string{fmt.Sprintf("Search results for: %s (stub)", query)}, nil
}


