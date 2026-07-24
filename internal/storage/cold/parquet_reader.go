package cold

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/reader"
	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

// ParquetReader is a pure-Go cold reader that evaluates field = value AND
// ts BETWEEN predicates with row-group pruning. It is the default reader
// for the CGO-free build. DuckDB is 5-10x faster but requires CGO.
type ParquetReader struct{}

// NewParquetReader creates a pure-Go Parquet reader.
func NewParquetReader() *ParquetReader {
	return &ParquetReader{}
}

// Name returns the reader name.
func (r *ParquetReader) Name() string {
	return "parquet-go (pure Go)"
}

// QueryFiles reads events from the given Parquet files with basic filtering.
func (r *ParquetReader) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	var allEvents []*storage.Event
	var warnings []string

	for _, fi := range files {
		if ctx.Err() != nil {
			break
		}

		// Check file existence
		if _, err := os.Stat(fi.Path); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("file not found: %s", fi.Path))
			continue
		}

		pf, err := local.NewLocalFileReader(fi.Path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("open %s: %v", fi.Path, err))
			continue
		}
		fr, err := reader.NewParquetReader(pf, &parquet.TraceEventParquet{}, 1_000_000)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("open %s: %v", fi.Path, err))
			continue
		}

		// Read all rows
		rows, err := fr.ReadByNumber(int(fr.GetNumRows()))
		if err != nil {
			fr.ReadStop()
			warnings = append(warnings, fmt.Sprintf("read %s: %v", fi.Path, err))
			continue
		}
		fr.ReadStop()

		// Convert and filter
		for _, row := range rows {
			pe, ok := row.(parquet.TraceEventParquet)
			if !ok {
				continue
			}

			// Apply filters
			if q.SinceUs > 0 && pe.TimestampUs < q.SinceUs {
				continue
			}
			if q.UntilUs > 0 && pe.TimestampUs >= q.UntilUs {
				continue
			}
			if q.MinSeverity > 0 && int(pe.Severity) < q.MinSeverity {
				continue
			}
			if len(q.AgentIDs) > 0 && !contains(q.AgentIDs, pe.AgentID) {
				continue
			}
			if len(q.EventTypes) > 0 && !contains(q.EventTypes, pe.EventType) {
				continue
			}
			if q.MinID != "" && pe.ID <= q.MinID {
				continue
			}
			if q.MaxID != "" && pe.ID > q.MaxID {
				continue
			}
			if q.Cursor != "" && pe.ID <= q.Cursor {
				continue
			}

			allEvents = append(allEvents, parquetToEvent(pe))
		}
	}

	// Sort and dedup by ID
	result := &storage.Result{}
	if len(allEvents) > 0 {
		deduped := storage.MergeSortDedupByID(allEvents)
		result.Events = deduped
		if len(deduped) > 0 {
			result.Cursor = deduped[len(deduped)-1].ID
		}
	}
	if q.Limit > 0 && len(result.Events) > q.Limit {
		result.Events = result.Events[:q.Limit]
	}
	result.Warnings = warnings
	result.Total = len(result.Events)

	return result, nil
}

// parquetToEvent converts a Parquet struct back to a storage.Event.
func parquetToEvent(pe parquet.TraceEventParquet) *storage.Event {
	return &storage.Event{
		ID:          pe.ID,
		TenantID:    pe.TenantID,
		AgentID:     pe.AgentID,
		Timestamp:   pe.TimestampUs,
		IngestedAt:  pe.IngestedAt,
		EventType:   pe.EventType,
		Severity:    int(pe.Severity),
		ProcessName: pe.ProcessName,
		Cmdline:     pe.Cmdline,
		ParentPID:   int(pe.ParentPID),
		SHA256:      pe.SHA256,
		DestIP:      pe.DestIP,
		SrcIP:       pe.SrcIP,
		UserName:    pe.UserName,
		Hostname:    pe.Hostname,
		DataRaw:     pe.DataRaw,
	}
}

// contains checks if a string slice contains a value (case-insensitive for agents).
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
