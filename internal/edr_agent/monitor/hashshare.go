package monitor

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	multicastAddr = "239.0.0.88:1980"
	tcpListenAddr = ":1981"
	multicastTTL  = 5 * time.Minute
)

type HashVerdict struct {
	SHA256    string `json:"sha256"`
	Verdict   string `json:"verdict"`
	Severity  int    `json:"severity"`
	Timestamp int64  `json:"ts"`
	AgentID   string `json:"agent_id,omitempty"`
}

type HashShare struct {
	cache      *ScanCache
	mu         sync.Mutex
	udpConn    *net.UDPConn
	tcpLn      net.Listener
	started    bool
	done       chan struct{}
	agentID    string
	dataDir    string
	shareMode  string
}

func NewHashShare(cache *ScanCache, agentID, dataDir string) *HashShare {
	return &HashShare{
		cache:   cache,
		done:    make(chan struct{}),
		agentID: agentID,
		dataDir: dataDir,
	}
}

func (hs *HashShare) Start() error {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.started {
		return nil
	}

	if hs.tryUDP() {
		hs.shareMode = "udp"
		go hs.listenUDP()
	}
	if hs.tryTCP() {
		hs.shareMode = "tcp+udp"
		go hs.listenTCP()
	}

	if hs.shareMode == "" {
		log.Printf("[hashshare] network unavailable — using file exchange")
	}

	hs.started = true
	log.Printf("[hashshare] active (mode=%s)", hs.shareMode)
	return nil
}

func (hs *HashShare) Stop() {
	if hs.udpConn != nil {
		hs.udpConn.Close()
	}
	if hs.tcpLn != nil {
		hs.tcpLn.Close()
	}
}

func (hs *HashShare) Broadcast(sha256, verdict string, severity int) {
	verdictEntry := HashVerdict{
		SHA256: sha256, Verdict: verdict,
		Severity: severity, Timestamp: time.Now().Unix(),
		AgentID: hs.agentID,
	}
	data, err := json.Marshal(verdictEntry)
	if err != nil {
		return
	}

	if hs.udpConn != nil {
		hs.udpConn.SetWriteDeadline(time.Now().Add(time.Second))
		hs.udpConn.Write(data)
	}
	hs.writeToFile(sha256, verdict, severity)
}

func (hs *HashShare) tryUDP() bool {
	addr, err := net.ResolveUDPAddr("udp", multicastAddr)
	if err != nil {
		return false
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	hs.udpConn = conn
	return true
}

func (hs *HashShare) tryTCP() bool {
	ln, err := net.Listen("tcp", tcpListenAddr)
	if err != nil {
		return false
	}
	hs.tcpLn = ln
	return true
}

func (hs *HashShare) listenUDP() {
	defer hs.udpConn.Close()
	buf := make([]byte, 2048)
	for {
		hs.udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := hs.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		hs.processVerdict(buf[:n])
	}
}

func (hs *HashShare) listenTCP() {
	for {
		conn, err := hs.tcpLn.Accept()
		if err != nil {
			return
		}
		go hs.handleTCPConn(conn)
	}
}

func (hs *HashShare) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		hs.processVerdict(scanner.Bytes())
	}
}

func (hs *HashShare) processVerdict(data []byte) {
	var v HashVerdict
	if err := json.Unmarshal(data, &v); err != nil {
		return
	}
	if v.AgentID == hs.agentID {
		return
	}
	if time.Since(time.Unix(v.Timestamp, 0)) > multicastTTL {
		return
	}

	hs.cache.mu.Lock()
	hs.cache.entries[v.SHA256] = &ScanCacheEntry{
		Hash: v.SHA256,
		Matches: []*YaraRule{{
			Name:    "peer_" + v.Verdict,
			Matcher: yaraString{[]byte(v.SHA256)},
		}},
		CachedAt: time.Now(),
	}
	hs.cache.mu.Unlock()
}

func (hs *HashShare) writeToFile(sha256, verdict string, severity int) {
	if hs.dataDir == "" {
		return
	}
	dir := filepath.Join(hs.dataDir, "verdicts")
	os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, sha256+".verdict")
	v := HashVerdict{SHA256: sha256, Verdict: verdict, Severity: severity, Timestamp: time.Now().Unix()}
	data, _ := json.Marshal(v)
	os.WriteFile(path, data, 0600)
}

func (hs *HashShare) readFromFile(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 10 || e.Name()[len(e.Name())-8:] != ".verdict" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var v HashVerdict
		if err := json.Unmarshal(data, &v); err != nil {
			continue
		}
		if time.Since(time.Unix(v.Timestamp, 0)) > multicastTTL {
			os.Remove(path)
			continue
		}
		hs.cache.mu.Lock()
		hs.cache.entries[v.SHA256] = &ScanCacheEntry{
			Hash: v.SHA256,
			Matches: []*YaraRule{{
				Name: "file_" + v.Verdict,
				Matcher: yaraString{[]byte(v.SHA256)},
			}},
			CachedAt: time.Now(),
		}
		hs.cache.mu.Unlock()
	}
}
