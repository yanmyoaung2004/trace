package sift

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
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

// WarmBuiltin warms the hash cache from intel/seed-iocs.json, the single
// store of truth for builtin IOCs. There is intentionally no second builtin
// hash map here: confidences and reputations come from the JSON file, so a
// hash can never carry two conflicting verdicts.
//
// Exact hash match only: only hex digest entries (md5/sha1/sha256/sha512
// lengths) are warmed; IP/domain/CVE/MITRE entries in the seed file are
// skipped. Lookups via Get are exact-keyed ("hash:"+normalized), never
// substring.
func (hc *HashCache) WarmBuiltin(ctx context.Context) {
	path := seedIOCFile()
	if path == "" {
		log.Printf("[sift] seed-iocs.json not found; skipping builtin hash warm")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[sift] read seed IOCs: %v", err)
		return
	}
	var entries []struct {
		IOC        string  `json:"ioc"`
		Type       string  `json:"type"`
		Reputation string  `json:"reputation"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("[sift] parse seed IOCs: %v", err)
		return
	}
	for _, e := range entries {
		hash := strings.ToLower(strings.TrimSpace(e.IOC))
		if !isHexHash(hash) {
			continue
		}
		rep := e.Reputation
		if rep == "" {
			rep = "malicious"
		}
		exists, _ := hc.Get(ctx, hash)
		if exists != nil {
			continue
		}
		hc.Set(ctx, &HashReputation{
			Hash:       hash,
			Reputation: rep,
			Source:     "builtin",
			Malicious:  1,
			Total:      1,
			Confidence: e.Confidence,
		}, 86400*30)
	}
}

// seedIOCFile locates intel/seed-iocs.json by walking up from the working
// directory (covers `go test` in internal/sift and binaries launched from
// the repo root) and falling back to the executable's directory. Empty when
// not found; WarmBuiltin then warms nothing.
func seedIOCFile() string {
	var candidates []string
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for range 6 {
			candidates = append(candidates, filepath.Join(dir, "intel", "seed-iocs.json"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "intel", "seed-iocs.json"))
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// isHexHash reports whether s is a hex digest of a known hash length
// (md5/sha1/sha256/sha512). Used to warm hash entries only.
func isHexHash(s string) bool {
	switch len(s) {
	case 32, 40, 64, 128:
	default:
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
