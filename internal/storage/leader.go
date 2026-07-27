package storage

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NodeRole defines the TSE node's role in active-passive mode.
type NodeRole string

const (
	NodeRoleLeader   NodeRole = "leader"
	NodeRoleFollower NodeRole = "follower"
	NodeRoleAuto     NodeRole = "auto"
)

// LeaderElector manages leader election via S3 heartbeat files.
// The leader writes its timestamp and node ID to s3://bucket/.leader/
// every heartbeatInterval. Followers watch and promote themselves
// if the leader's heartbeat is older than failoverTimeout.
type LeaderElector struct {
	s3                *S3Client
	nodeID            string
	role              NodeRole
	heartbeatInterval time.Duration
	failoverTimeout   time.Duration
	stopCh            chan struct{}
	doneCh            chan struct{}
	mu                sync.RWMutex
	isLeader          bool
}

// NewLeaderElector creates a leader elector.
func NewLeaderElector(s3 *S3Client, role NodeRole) *LeaderElector {
	hostname, _ := os.Hostname()
	nodeID := fmt.Sprintf("%s-%d", hostname, rand.Intn(10000))
	return &LeaderElector{
		s3:                s3,
		nodeID:            nodeID,
		role:              role,
		heartbeatInterval: 5 * time.Second,
		failoverTimeout:   15 * time.Second,
		stopCh:            make(chan struct{}),
		doneCh:            make(chan struct{}),
		isLeader:          role == NodeRoleLeader,
	}
}

// IsLeader returns true if this node is currently the leader.
func (l *LeaderElector) IsLeader() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.isLeader
}

// NodeID returns this node's unique identifier.
func (l *LeaderElector) NodeID() string { return l.nodeID }

// SetHeartbeatInterval overrides the default 5s heartbeat interval (for testing).
func (l *LeaderElector) SetHeartbeatInterval(d time.Duration) { l.heartbeatInterval = d }

// SetFailoverTimeout overrides the default 15s failover timeout (for testing).
func (l *LeaderElector) SetFailoverTimeout(d time.Duration) { l.failoverTimeout = d }

// Run starts the leader election loop. Blocks until context is cancelled.
func (l *LeaderElector) Run(ctx context.Context) error {
	ticker := time.NewTicker(l.heartbeatInterval)
	defer ticker.Stop()
	defer close(l.doneCh)
	defer log.Printf("[leader] stopped (role=%s, node=%s)", l.role, l.nodeID)

	log.Printf("[leader] started (role=%s, node=%s)", l.role, l.nodeID)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.stopCh:
			return nil
		case <-ticker.C:
			l.tick(ctx)
		}
	}
}

// Stop stops the leader election loop.
func (l *LeaderElector) Stop(ctx context.Context) error {
	close(l.stopCh)
	select {
	case <-l.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *LeaderElector) tick(ctx context.Context) {
	switch l.role {
	case NodeRoleLeader:
		l.heartbeat(ctx)
	case NodeRoleFollower, NodeRoleAuto:
		l.checkLeader(ctx)
	}
}

// heartbeat writes the current timestamp to S3.
func (l *LeaderElector) heartbeat(ctx context.Context) {
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	nodePath := fmt.Sprintf(".leader/%s", l.nodeID)

	if err := l.s3.Upload(".leader/ts", []byte(ts)); err != nil {
		log.Printf("[leader] heartbeat write failed: %v", err)
		return
	}
	if err := l.s3.Upload(nodePath, []byte(l.nodeID)); err != nil {
		log.Printf("[leader] heartbeat node write failed: %v", err)
	}
}

// checkLeader reads the leader heartbeat and promotes self if stale.
func (l *LeaderElector) checkLeader(ctx context.Context) {
	data, err := l.s3.Download(".leader/ts")
	if err != nil {
		// No leader heartbeat — try to become leader
		l.promote(ctx)
		return
	}

	tsStr := strings.TrimSpace(string(data))
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		l.promote(ctx)
		return
	}

	age := time.Now().UnixMilli() - ts
	if age > l.failoverTimeout.Milliseconds() {
		log.Printf("[leader] heartbeat stale by %dms (timeout=%v), promoting self", age, l.failoverTimeout)
		l.promote(ctx)
	}
}

// promote makes this node the leader.
func (l *LeaderElector) promote(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isLeader {
		return
	}
	log.Printf("[leader] promoting self to leader (node=%s)", l.nodeID)
	l.isLeader = true
}
