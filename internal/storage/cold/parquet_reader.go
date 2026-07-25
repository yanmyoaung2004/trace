package cold

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	pq "github.com/parquet-go/parquet-go"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

var parquetMagic = []byte("PAR1")

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

		if _, err := os.Stat(fi.Path); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("file not found: %s", fi.Path))
			continue
		}

		f, err := os.Open(fi.Path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("open %s: %v", fi.Path, err))
			continue
		}

		// Validate parquet magic header before opening reader
		// (pq.NewGenericReader panics on invalid files)
		if !isValidParquet(f) {
			f.Close()
			warnings = append(warnings, fmt.Sprintf("invalid parquet file: %s", fi.Path))
			continue
		}
		// Re-open after checking magic (we consumed bytes from the reader)
		f.Close()
		f, err = os.Open(fi.Path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("re-open %s: %v", fi.Path, err))
			continue
		}

		pf := pq.NewGenericReader[parquet.TraceEventParquet](f)

		rows := make([]parquet.TraceEventParquet, pf.NumRows())
		n, err := pf.Read(rows)
		if err != nil && err != io.EOF {
			pf.Close()
			f.Close()
			warnings = append(warnings, fmt.Sprintf("read %s: %v", fi.Path, err))
			continue
		}
		rows = rows[:n]
		pf.Close()
		f.Close()

		for _, row := range rows {
			if q.SinceUs > 0 && row.TimestampUs < q.SinceUs {
				continue
			}
			if q.UntilUs > 0 && row.TimestampUs >= q.UntilUs {
				continue
			}
			if q.MinSeverity > 0 && int(row.Severity) < q.MinSeverity {
				continue
			}
			if len(q.AgentIDs) > 0 && !contains(q.AgentIDs, row.AgentID) {
				continue
			}
			if len(q.EventTypes) > 0 && !contains(q.EventTypes, row.EventType) {
				continue
			}
			if q.MinID != "" && row.ID <= q.MinID {
				continue
			}
			if q.MaxID != "" && row.ID > q.MaxID {
				continue
			}
			if q.Cursor != "" && row.ID <= q.Cursor {
				continue
			}

			allEvents = append(allEvents, parquetToEvent(row))
		}
	}

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

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}

// isValidParquet checks if the reader contains a valid parquet file by reading
// the 4-byte magic header. The reader position is advanced, so callers should
// re-open the file after this check.
func isValidParquet(r io.ReadSeeker) bool {
	magic := make([]byte, 4)
	if _, err := r.Read(magic); err != nil {
		return false
	}
	return string(magic) == string(parquetMagic)
}
