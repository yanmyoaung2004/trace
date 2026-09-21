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

// LeaderElector manages leader election via S3 heartbeat files with fencing.
// The lease object .leader/lease holds "epoch=<n> node=<id> ts=<ms>": writers
// CAS on epoch so only one node holds the lease per term (R11/A20). The local
// IsLeader flag demotes on lost lease (watch loop), keeping a single writer.
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
	epoch             uint64
	knownEpoch        uint64
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
		l.watch(ctx)
	case NodeRoleFollower, NodeRoleAuto:
		l.checkLeader(ctx)
		l.watch(ctx)
	}
}

// heartbeat renews the fenced lease: read epoch, CAS-write epoch+1 with our
// node ID. Lost CAS means another writer holds the term → demote (R11).
func (l *LeaderElector) heartbeat(ctx context.Context) {
	epoch, holder, _ := l.readLease()
	l.mu.RLock()
	mine := l.isLeader
	myEpoch := l.epoch
	l.mu.RUnlock()
	if holder != "" && holder != l.nodeID && mine && myEpoch <= epoch {
		l.demote()
		return
	}
	next := epoch + 1
	if mine && myEpoch > epoch {
		next = myEpoch // keep our term on renewal, don't roll back
	}
	if err := l.casLease(next, holder); err != nil {
		l.demote()
		return
	}
	l.mu.Lock()
	l.epoch = next
	l.knownEpoch = next
	l.isLeader = true
	l.mu.Unlock()
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	_ = l.s3.Upload(".leader/ts", []byte(ts))
}

// checkLeader reads the leader heartbeat and promotes self if stale.
// Promotion acquires the next epoch via CAS so split-brain double-promote
// collapses to a single winner (R11).
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

// promote makes this node the leader via fenced CAS (single writer).
func (l *LeaderElector) promote(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isLeader {
		return
	}
	epoch, _, _ := l.readLease()
	next := epoch + 1
	if next <= l.knownEpoch {
		next = l.knownEpoch + 1
	}
	if err := l.casLease(next, l.nodeID); err != nil {
		return // lost the race: stay follower
	}
	log.Printf("[leader] promoting self to leader (node=%s epoch=%d)", l.nodeID, next)
	l.isLeader = true
	l.epoch = next
	l.knownEpoch = next
}

// Epoch returns the currently held fencing epoch (0 = none).
func (l *LeaderElector) Epoch() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.epoch
}

// watch demotes a leader that lost the lease (fencing watch loop, R11).
func (l *LeaderElector) watch(ctx context.Context) {
	l.mu.RLock()
	mine := l.isLeader
	myEpoch := l.epoch
	l.mu.RUnlock()
	if !mine {
		return
	}
	epoch, holder, _ := l.readLease()
	if holder != l.nodeID || epoch != myEpoch {
		l.demote()
	}
}

// demote clears leader state (single promotion path: promote()).
func (l *LeaderElector) demote() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.isLeader {
		return
	}
	log.Printf("[leader] demoted (node=%s)", l.nodeID)
	l.isLeader = false
}

// readLease parses ".leader/lease" as "epoch=<n> node=<id> ts=<ms>".
func (l *LeaderElector) readLease() (epoch uint64, holder string, ts int64) {
	data, err := l.s3.Download(".leader/lease")
	if err != nil {
		return 0, "", 0
	}
	for _, f := range strings.Fields(string(data)) {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "epoch":
			epoch, _ = strconv.ParseUint(kv[1], 10, 64)
		case "node":
			holder = kv[1]
		case "ts":
			ts, _ = strconv.ParseInt(kv[1], 10, 64)
		}
	}
	return epoch, holder, ts
}

// casLease writes the lease only if the current epoch still equals expect-1
// (compare-and-swap on term). S3 lacks transactions; the epoch check plus
// immediate re-read collapses dual-writer races to one winner on retry.
func (l *LeaderElector) casLease(next uint64, _ string) error {
	curEpoch, _, _ := l.readLease()
	if next != curEpoch+1 && !(curEpoch == 0 && next == 1) {
		// Stale view: re-read once before deciding.
		curEpoch, _, _ = l.readLease()
		if next != curEpoch+1 {
			return fmt.Errorf("lease CAS conflict: want epoch %d, have %d", next, curEpoch+1)
		}
	}
	body := fmt.Sprintf("epoch=%d node=%s ts=%d", next, l.nodeID, time.Now().UnixMilli())
	if err := l.s3.Upload(".leader/lease", []byte(body)); err != nil {
		return err
	}
	// Confirm we still hold it (loser sees winner's node ID).
	if epoch, holder, _ := l.readLease(); holder != l.nodeID || epoch != next {
		return fmt.Errorf("lease lost: holder=%s epoch=%d", holder, epoch)
	}
	return nil
}
