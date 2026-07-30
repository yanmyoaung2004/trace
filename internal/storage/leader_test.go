package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func s3TestServer(t *testing.T) (*httptest.Server, *S3Client) {
	t.Helper()
	var mu sync.Mutex
	store := make(map[string][]byte)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/test-bucket/")
		switch r.Method {
		case "PUT":
			data, _ := io.ReadAll(r.Body)
			mu.Lock()
			store[key] = data
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "GET":
			mu.Lock()
			data, ok := store[key]
			mu.Unlock()
			if ok {
				w.WriteHeader(http.StatusOK)
				w.Write(data)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	cfg := S3Config{Bucket: "test-bucket", Endpoint: strings.TrimPrefix(server.URL, "http://")}
	client := NewS3Client(cfg)
	client.client = server.Client()
	return server, client
}

func TestLeaderElector_LeaderHeartbeat(t *testing.T) {
	server, s3 := s3TestServer(t)
	defer server.Close()

	leader := NewLeaderElector(s3, NodeRoleLeader)
	leader.SetHeartbeatInterval(50 * time.Millisecond)
	leader.SetFailoverTimeout(time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go leader.Run(ctx)

	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Verify heartbeat was written
	data, err := s3.Download(".leader/ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected heartbeat timestamp")
	}
}

func TestLeaderElector_FollowerDetectsStaleHeartbeat(t *testing.T) {
	server, s3 := s3TestServer(t)
	defer server.Close()

	// Write an old heartbeat
	s3.Upload(".leader/ts", []byte("0"))

	follower := NewLeaderElector(s3, NodeRoleFollower)
	follower.SetHeartbeatInterval(50 * time.Millisecond)
	follower.SetFailoverTimeout(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go follower.Run(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	if !follower.IsLeader() {
		t.Error("expected follower to promote itself after stale heartbeat")
	}
}

func TestLeaderElector_FollowerFollowsActiveLeader(t *testing.T) {
	server, s3 := s3TestServer(t)
	defer server.Close()

	// Write a recent heartbeat
	s3.Upload(".leader/ts", []byte("9999999999999"))

	follower := NewLeaderElector(s3, NodeRoleFollower)
	follower.SetHeartbeatInterval(50 * time.Millisecond)
	follower.SetFailoverTimeout(10 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go follower.Run(ctx)

	time.Sleep(150 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	if follower.IsLeader() {
		t.Error("expected follower to NOT promote with active leader")
	}
}

func TestLeaderElector_NodeID(t *testing.T) {
	leader := NewLeaderElector(nil, NodeRoleLeader)
	if leader.NodeID() == "" {
		t.Error("expected non-empty node ID")
	}
}

func TestLeaderElector_Failover(t *testing.T) {
	server, s3 := s3TestServer(t)
	defer server.Close()

	// Node 1: starts as leader
	node1 := NewLeaderElector(s3, NodeRoleLeader)
	node1.SetHeartbeatInterval(50 * time.Millisecond)

	// Node 2: starts as follower
	node2 := NewLeaderElector(s3, NodeRoleFollower)
	node2.SetHeartbeatInterval(50 * time.Millisecond)
	node2.SetFailoverTimeout(150 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start node1 first, wait for heartbeat to be established
	go node1.Run(ctx)
	time.Sleep(150 * time.Millisecond)

	// Verify node1 has written heartbeat
	hbData, hbErr := s3.Download(".leader/ts")
	if hbErr != nil || len(hbData) == 0 {
		t.Fatal("node1 should have written heartbeat")
	}

	// Now start node2 — it should see node1's heartbeat and stay follower
	go node2.Run(ctx)
	time.Sleep(150 * time.Millisecond)

	if !node1.IsLeader() {
		t.Fatal("node1 should be leader")
	}
	if node2.IsLeader() {
		t.Fatal("node2 should be follower initially")
	}

	// Stop node1 (simulate crash)
	stopCtx, stopCancel := context.WithTimeout(ctx, time.Second)
	defer stopCancel()
	node1.Stop(stopCtx)

	// Wait for node2 to detect stale heartbeat and promote
	time.Sleep(300 * time.Millisecond)

	if !node2.IsLeader() {
		t.Fatal("node2 should have promoted to leader after node1 failure")
	}

	// Verify node2 wrote its heartbeat
	hb2, err2 := s3.Download(".leader/ts")
	if err2 != nil {
		t.Fatal(err2)
	}
	if len(hb2) == 0 {
		t.Error("expected heartbeat from new leader")
	}
}

func TestLeaderElector_Stop(t *testing.T) {
	server, s3 := s3TestServer(t)
	defer server.Close()

	leader := NewLeaderElector(s3, NodeRoleLeader)
	leader.SetHeartbeatInterval(time.Hour) // won't fire

	ctx := context.Background()
	go leader.Run(ctx)

	stopCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	if err := leader.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}
