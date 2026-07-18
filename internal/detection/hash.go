package detection

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

type HashReputation struct {
	Hash         string    `json:"hash"`
	Reputation   string    `json:"reputation"`
	Source       string    `json:"source"`
	Malicious    int       `json:"malicious"`
	Total        int       `json:"total"`
	Confidence   float64   `json:"confidence"`
	LastChecked  time.Time `json:"last_checked"`
}

type HashCache struct {
	db *sql.DB
	mu sync.Mutex
}

func NewHashCache(database *sql.DB) *HashCache {
	return &HashCache{db: database}
}

func (hc *HashCache) Get(ctx context.Context, hash string) (*HashReputation, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	var data string

	err := hc.db.QueryRowContext(ctx,
		`SELECT value FROM cache WHERE key = ? AND ttl > CAST(strftime('%s','now') AS INTEGER)`,
		"hash:"+hash).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var rep HashReputation
	if err := json.Unmarshal([]byte(data), &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

func (hc *HashCache) Set(ctx context.Context, rep *HashReputation, ttl int) {
	data, _ := json.Marshal(rep)
	hc.mu.Lock()
	hc.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO cache (key, value, ttl) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) + ?)`,
		"hash:"+rep.Hash, string(data), ttl)
	hc.mu.Unlock()
}

func (hc *HashCache) WarmBuiltin(ctx context.Context) {
	builtin := map[string]string{
		"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Mimikatz",
		"e99a18c428cb38d5f260853678922e03": "EICAR test file",
	}

	for hash, name := range builtin {
		exists, _ := hc.Get(ctx, hash)
		if exists != nil {
			continue
		}
		hc.Set(ctx, &HashReputation{
			Hash:       hash,
			Reputation: "malicious",
			Source:     "builtin",
			Malicious:  1,
			Total:      1,
			Confidence: 0.9,
		}, 86400*30)
		_ = name
	}
}
