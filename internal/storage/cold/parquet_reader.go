package cold

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	pq "github.com/parquet-go/parquet-go"

	"github.com/yanmyoaung2004/trace/internal/storage"
	"github.com/yanmyoaung2004/trace/internal/storage/parquet"
)

var parquetMagic = []byte("PAR1")

// column indexes in TraceEventParquet (0-indexed by leaf column order)
const (
	colID          = 0
	colTenantID    = 1
	colAgentID     = 2
	colTimestampUs = 3
	colIngestedAt  = 4
	colEventType   = 5
	colSeverity    = 6
)

// ParquetReader is a pure-Go cold reader with row-group pruning and S3 support.
type ParquetReader struct {
	s3 *storage.S3Client // set when S3 cold storage is enabled
}

func NewParquetReader() *ParquetReader {
	return &ParquetReader{}
}

// SetS3 attaches an S3 client so the reader can download files from s3:// paths.
func (r *ParquetReader) SetS3(s3 *storage.S3Client) {
	r.s3 = s3
}

func (r *ParquetReader) Name() string {
	return "parquet-go (pure Go, pruned)"
}

// QueryFiles reads events from Parquet files with row-group pruning.
func (r *ParquetReader) QueryFiles(ctx context.Context, files []storage.FileInfo, q storage.Query) (*storage.Result, error) {
	q = q.ApplyDefaults()
	var allEvents []*storage.Event
	var warnings []string

	for _, fi := range files {
		if ctx.Err() != nil {
			break
		}
		if q.Limit > 0 && len(allEvents) >= q.Limit*2 {
			break // early terminate across files (P-H2)
		}
		// Resolve path — download from S3 if needed. The staged temp uses a
		// crypto-random unique name (O_EXCL, 0600); the resolved local path is
		// opened below, never the s3:// URI (fix s3:// open bug + hex(len)
		// collision class: temps keyed on random bytes, not content length).
		filePath := fi.Path
		var stagedTmp string
		if storage.IsS3Path(filePath) {
			if r.s3 == nil {
				warnings = append(warnings, fmt.Sprintf("S3 not configured, can't read %s", filePath))
				continue
			}
			_, s3Key := storage.ParseS3Path(filePath)
			data, err := r.s3.Download(s3Key)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("s3 download %s: %v", filePath, err))
				continue
			}
			tmpFile, err := stageS3Bytes(data)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("s3 temp stage: %v", err))
				continue
			}
			stagedTmp = tmpFile
			defer os.Remove(stagedTmp)
			filePath = tmpFile
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("file not found: %s", filePath))
			continue
		}

		f, err := os.Open(filePath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("open %s: %v", fi.Path, err))
			continue
		}

		if !isValidParquet(f) {
			f.Close()
			warnings = append(warnings, fmt.Sprintf("invalid parquet file: %s", fi.Path))
			continue
		}
		f.Close()

		f, err = os.Open(filePath)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("re-open %s: %v", fi.Path, err))
			continue
		}

		pf := pq.NewGenericReader[parquet.TraceEventParquet](f)
		fileView := pf.File()
		rowGroups := fileView.RowGroups()

		for _, rg := range rowGroups {
			if ctx.Err() != nil {
				break
			}

			// Row-group pruning: skip if column stats prove no match
			if !rgMayMatch(rg, q) {
				continue
			}

			rgReader := pq.NewGenericRowGroupReader[parquet.TraceEventParquet](rg)
			// Stream in bounded batches (P-H2) with early termination at the
			// query limit instead of materializing whole row groups.
			const batchRows = 4096
			buf := make([]parquet.TraceEventParquet, batchRows)
			streamDone := false
			for !streamDone {
				if ctx.Err() != nil {
					break
				}
				if q.Limit > 0 && len(allEvents) >= q.Limit*2 {
					streamDone = true
					break
				}
				n, rerr := rgReader.Read(buf)
				for _, row := range buf[:n] {
					if q.TenantID != "" && row.TenantID != q.TenantID {
						continue
					}
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
					if q.Limit > 0 && len(allEvents) >= q.Limit*2 {
						streamDone = true
						break
					}
				}
				if rerr == io.EOF || n == 0 {
					break
				}
				if rerr != nil {
					warnings = append(warnings, fmt.Sprintf("read row group in %s: %v", fi.Path, rerr))
					break
				}
			}
			rgReader.Close()
			if q.Limit > 0 && len(allEvents) >= q.Limit*2 {
				break
			}
		}

		pf.Close()
		f.Close()
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

// stageS3Bytes stages downloaded S3 bytes in a unique O_EXCL 0600 temp file.
// The name derives from crypto-random bytes (never hex(len)): concurrent
// downloads of same-sized objects no longer collide (cold temp fix).
func stageS3Bytes(data []byte) (string, error) {
	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", fmt.Errorf("s3 temp rand: %w", err)
	}
	tmpFile := fmt.Sprintf("%s%c%s-%s.parquet", os.TempDir(), os.PathSeparator, "trace-s3", hex.EncodeToString(rb[:]))
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("s3 temp create: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return "", fmt.Errorf("s3 temp write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return "", fmt.Errorf("s3 temp fsync: %w", err)
	}
	f.Close()
	return tmpFile, nil
}

// rgMayMatch checks if a row group could contain matching rows for the query.
// Uses parquet column statistics to skip row groups that can't possibly match.
func rgMayMatch(rg pq.RowGroup, q storage.Query) bool {
	chunks := rg.ColumnChunks()
	if len(chunks) <= max(max(colTimestampUs, colSeverity), colAgentID) {
		return true // can't check, assume match
	}

	if q.SinceUs > 0 || q.UntilUs > 0 {
		tsMin, tsMax := columnMinMax(chunks[colTimestampUs])
		if q.SinceUs > 0 && tsMax < q.SinceUs {
			return false
		}
		if q.UntilUs > 0 && tsMin >= q.UntilUs {
			return false
		}
	}

	if q.MinSeverity > 0 {
		_, sevMax := columnMinMax(chunks[colSeverity])
		if int32(sevMax) < int32(q.MinSeverity) {
			return false
		}
	}

	if len(q.AgentIDs) > 0 {
		agMin, agMax := columnMinMaxStr(chunks[colAgentID])
		if agMin != "" && agMax != "" {
			anyMatch := false
			for _, agent := range q.AgentIDs {
				if agent >= agMin && agent <= agMax {
					anyMatch = true
					break
				}
			}
			if !anyMatch {
				return false
			}
		}
	}

	return true
}

// columnMinMax returns the min and max int64 values from a column chunk's index.
func columnMinMax(chunk pq.ColumnChunk) (int64, int64) {
	colIdx, err := chunk.ColumnIndex()
	if err != nil {
		return 0, 0 // can't get stats, assume all
	}

	n := colIdx.NumPages()
	if n == 0 {
		return 0, 0
	}

	min := colIdx.MinValue(0).Int64()
	max := colIdx.MaxValue(0).Int64()

	for i := 1; i < n; i++ {
		if v := colIdx.MinValue(i).Int64(); v < min {
			min = v
		}
		if v := colIdx.MaxValue(i).Int64(); v > max {
			max = v
		}
	}

	return min, max
}

func parquetToEvent(pe parquet.TraceEventParquet) *storage.Event {
	e := &storage.Event{
		ID:          pe.ID,
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
	if pe.Annotations != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(pe.Annotations), &m); err == nil {
			e.Annotations = m
		}
	}
	return e
}
	for i := 1; i < n; i++ {
		if v := colIdx.MinValue(i).String(); v < min {
			min = v
		}
		if v := colIdx.MaxValue(i).String(); v > max {
			max = v
		}
	}
	return min, max
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}

func isValidParquet(r io.ReadSeeker) bool {
	magic := make([]byte, 4)
	if _, err := r.Read(magic); err != nil {
		return false
	}
	return string(magic) == string(parquetMagic)
}
