package monitor

import (
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"
)

const (
	multicastAddr = "239.0.0.88:1980"
	multicastTTL  = 5 * time.Minute
)

type HashVerdict struct {
	SHA256    string `json:"sha256"`
	Verdict   string `json:"verdict"`
	Severity  int    `json:"severity"`
	Timestamp int64  `json:"ts"`
}

type HashShare struct {
	cache   *ScanCache
	mu      sync.Mutex
	conn    *net.UDPConn
	started bool
	done    chan struct{}
}

func NewHashShare(cache *ScanCache) *HashShare {
	return &HashShare{
		cache: cache,
		done:  make(chan struct{}),
	}
}

func (hs *HashShare) Start() error {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.started {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", multicastAddr)
	if err != nil {
		log.Printf("[hashshare] resolve failed: %v", err)
		return err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("[hashshare] dial failed: %v (disabling)", err)
		return err
	}
	hs.conn = conn
	hs.started = true

	go hs.listen()
	log.Printf("[hashshare] active on %s", multicastAddr)
	return nil
}

func (hs *HashShare) Stop() {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.started {
		hs.started = false
		close(hs.done)
		if hs.conn != nil {
			hs.conn.Close()
		}
	}
}

func (hs *HashShare) Broadcast(sha256, verdict string, severity int) {
	if !hs.started || hs.conn == nil {
		return
	}
	v := HashVerdict{
		SHA256:    sha256,
		Verdict:   verdict,
		Severity:  severity,
		Timestamp: time.Now().Unix(),
	}
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	hs.conn.SetWriteDeadline(time.Now().Add(time.Second))
	hs.conn.Write(data)
}

func (hs *HashShare) listen() {
	addr, err := net.ResolveUDPAddr("udp", multicastAddr)
	if err != nil {
		return
	}

	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		log.Printf("[hashshare] listen failed: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadBuffer(65536)

	buf := make([]byte, 2048)
	for {
		select {
		case <-hs.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		var v HashVerdict
		if err := json.Unmarshal(buf[:n], &v); err != nil {
			continue
		}
		if time.Since(time.Unix(v.Timestamp, 0)) > multicastTTL {
			continue
		}

		hs.cache.mu.Lock()
		hs.cache.entries[v.SHA256] = &ScanCacheEntry{
			Hash: v.SHA256,
			Matches: []*YaraRule{{
				Name: "multicast_" + v.Verdict,
				Matcher: yaraString{[]byte(v.SHA256)},
			}},
			CachedAt: time.Now(),
		}
		hs.cache.mu.Unlock()
	}
}
