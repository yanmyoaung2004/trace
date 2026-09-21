package flusher

import (
	"sort"
	"time"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// groupKey identifies a (tenant, hour) group for batch accumulation.
type groupKey struct {
	TenantID string
	Hour     int64 // start of hour in epoch microseconds
}

// groupEvents groups events by (tenant_id, hour_of_timestamp).
func groupEvents(events []*storage.Event) map[groupKey][]*storage.Event {
	groups := make(map[groupKey][]*storage.Event)
	for _, e := range events {
		hk := truncateHour(e.Timestamp)
		key := groupKey{TenantID: e.TenantID, Hour: hk}
		groups[key] = append(groups[key], e)
	}
	return groups
}

// readyGroups returns groups that have enough data to flush.
// A group is ready when it accumulates row/byte volume (row/byte trigger)
// or ages past the hour boundary plus a straggler window (max-age trigger,
// P-H7). Small groups no longer stall behind a 256MB default.
func readyGroups(groups map[groupKey][]*storage.Event, targetSize int64) []groupKey {
	var ready []groupKey
	now := time.Now().UnixMicro()
	stragglerWindow := int64(5 * time.Minute) // 5 min in microseconds
	const minRowsReady = 1000
	const minBytesReady = int64(1 << 20) // 1MB floors the 256MB target

	for key, events := range groups {
		totalSize := estimateSize(events)
		hourEnd := key.Hour + int64(time.Hour/time.Microsecond)

		aged := now > hourEnd+stragglerWindow
		byVolume := int64(len(events)) >= minRowsReady || totalSize >= minBytesReady
		byTarget := totalSize >= targetSize
		if byTarget || (byVolume && aged) || (aged && len(events) > 0) {
			ready = append(ready, key)
		}
	}

	// Sort by hour for deterministic flush order
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].Hour != ready[j].Hour {
			return ready[i].Hour < ready[j].Hour
		}
		return ready[i].TenantID < ready[j].TenantID
	})

	return ready
}

// truncateHour rounds a timestamp down to the start of its hour.
func truncateHour(tsUs int64) int64 {
	return tsUs - (tsUs % int64(time.Hour/time.Microsecond))
}

// estimateSize estimates the uncompressed size of events.
func estimateSize(events []*storage.Event) int64 {
	var size int64
	for _, e := range events {
		size += 200 + int64(len(e.ID)+len(e.TenantID)+len(e.AgentID)+
			len(e.EventType)+len(e.ProcessName)+len(e.Cmdline)+
			len(e.SHA256)+len(e.DestIP)+len(e.SrcIP)+
			len(e.UserName)+len(e.Hostname)+len(e.DataRaw))
	}
	return size
}
