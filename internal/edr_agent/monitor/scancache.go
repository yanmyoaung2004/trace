package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

type ScanCacheEntry struct {
	Hash      string
	Matches   []*YaraRule
	CachedAt  time.Time
}

type ScanCache struct {
	mu       sync.RWMutex
	entries  map[string]*ScanCacheEntry
	ttl      time.Duration
	maxSize  int
	hits     int64
	misses   int64
}

func NewScanCache() *ScanCache {
	return &ScanCache{
		entries: make(map[string]*ScanCacheEntry),
		ttl:     1 * time.Hour,
		maxSize: 10000,
	}
}

func (sc *ScanCache) Get(path string, data []byte) ([]*YaraRule, bool) {
	fileHash := sha256Of(data)
	key := fmt.Sprintf("%s:%s", path, fileHash)

	sc.mu.RLock()
	entry, ok := sc.entries[key]
	sc.mu.RUnlock()

	if ok && time.Since(entry.CachedAt) < sc.ttl {
		sc.mu.Lock()
		sc.hits++
		sc.mu.Unlock()
		return entry.Matches, true
	}

	sc.mu.Lock()
	sc.misses++
	newEntry := &ScanCacheEntry{
		Hash:     fileHash,
		CachedAt: time.Now(),
	}
	if sc.misses%100 == 0 {
		sc.evictLocked()
	}
	sc.entries[key] = newEntry
	sc.mu.Unlock()

	return nil, false
}

func (sc *ScanCache) Set(path string, data []byte, matches []*YaraRule) {
	fileHash := sha256Of(data)
	key := fmt.Sprintf("%s:%s", path, fileHash)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.entries[key] = &ScanCacheEntry{
		Hash:     fileHash,
		Matches:  matches,
		CachedAt: time.Now(),
	}
}

func (sc *ScanCache) Invalidate(path string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for key := range sc.entries {
		if key == path || (len(key) > len(path)+1 && key[:len(path)+1] == path+":") {
			delete(sc.entries, key)
		}
	}
}

func (sc *ScanCache) evictLocked() {
	if len(sc.entries) <= sc.maxSize {
		return
	}
	cutoff := time.Now().Add(-sc.ttl)
	for key, entry := range sc.entries {
		if entry.CachedAt.Before(cutoff) {
			delete(sc.entries, key)
		}
		if len(sc.entries) <= sc.maxSize*3/4 {
			break
		}
	}
}

func (sc *ScanCache) Stats() (hits, misses int64) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.hits, sc.misses
}

func sha256Of(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Of(data), nil
}
