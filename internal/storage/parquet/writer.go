package parquet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	pq "github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress"
	pqbrotli "github.com/parquet-go/parquet-go/compress/brotli"
	pqgzip "github.com/parquet-go/parquet-go/compress/gzip"
	pqlz4 "github.com/parquet-go/parquet-go/compress/lz4"
	pqsnappy "github.com/parquet-go/parquet-go/compress/snappy"
	pqzstd "github.com/parquet-go/parquet-go/compress/zstd"

	"github.com/yanmyoaung2004/trace/internal/storage"
)

// ParquetWriter writes events to Parquet v2 files with ZSTD compression.
// It implements the "write to temp → fsync → atomic rename → manifest commit" pattern.
type ParquetWriter struct {
	opts       ParquetOptions
	tempDir    string
	outputDir  string
	targetSize int64
}

// NewParquetWriter creates a Parquet writer.
// tempDir is where temp files are written before atomic rename to outputDir.
func NewParquetWriter(tempDir, outputDir string, opts ParquetOptions) *ParquetWriter {
	if opts.RowGroupSize <= 0 {
		opts.RowGroupSize = 1_000_000
	}
	targetSize := int64(256 << 20)
	return &ParquetWriter{
		opts:       opts,
		tempDir:    tempDir,
		outputDir:  outputDir,
		targetSize: targetSize,
	}
}

// WriteBatch writes events to a Parquet file. The events are sorted
// by (agent_id, timestamp) within the file for optimal compression
// and row-group pruning.
func (w *ParquetWriter) WriteBatch(ctx context.Context, events []*storage.Event, partitionKey string) (*storage.FileResult, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("empty batch")
	}

	parqEvents := make([]TraceEventParquet, len(events))
	for i, e := range events {
		parqEvents[i] = eventToParquet(e)
	}

	sort.Slice(parqEvents, func(i, j int) bool {
		if parqEvents[i].AgentID != parqEvents[j].AgentID {
			return parqEvents[i].AgentID < parqEvents[j].AgentID
		}
		return parqEvents[i].TimestampUs < parqEvents[j].TimestampUs
	})

	ts := time.Now().UnixMicro()
	fileName := fmt.Sprintf("part-%x.parquet", ts)
	tempPath := filepath.Join(w.tempDir, fileName+"."+fmt.Sprintf("%d", os.Getpid()))
	finalPath := filepath.Join(w.outputDir, partitionKey, fileName)

	if err := os.MkdirAll(filepath.Dir(finalPath), 0700); err != nil {
		return nil, fmt.Errorf("output dir: %w", err)
	}
	os.MkdirAll(w.tempDir, 0700)

	fw, err := os.Create(tempPath)
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}

	compression := parquetCompression(w.opts.Compression)
	pw := pq.NewGenericWriter[TraceEventParquet](fw,
		pq.Compression(compression),
		pq.PageBufferSize(64*1024),
	)

	for _, row := range parqEvents {
		if _, err := pw.Write([]TraceEventParquet{row}); err != nil {
			pw.Close()
			fw.Close()
			os.Remove(tempPath)
			return nil, fmt.Errorf("write: %w", err)
		}
	}

	if err := pw.Close(); err != nil {
		fw.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("close writer: %w", err)
	}

	if err := fw.Sync(); err != nil {
		fw.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("fsync: %w", err)
	}
	fw.Close()

	hash, err := fileSHA256(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("sha256: %w", err)
	}

	info, err := os.Stat(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("stat: %w", err)
	}

	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("rename: %w", err)
	}

	minID := parqEvents[0].ID
	maxID := parqEvents[len(parqEvents)-1].ID
	minTS := parqEvents[0].TimestampUs
	maxTS := parqEvents[len(parqEvents)-1].TimestampUs

	result := &storage.FileResult{
		Path:             finalPath,
		RowCount:         len(parqEvents),
		CompressedSize:   info.Size(),
		UncompressedSize: uncompressedSize(parqEvents),
		SHA256:           hash,
		MinTimestampUs:   minTS,
		MaxTimestampUs:   maxTS,
		MinEventID:       minID,
		MaxEventID:       maxID,
	}

	return result, nil
}

// Close releases any resources held by the writer.
func (w *ParquetWriter) Close() error {
	return nil
}

func eventToParquet(e *storage.Event) TraceEventParquet {
	return TraceEventParquet{
		ID:          e.ID,
		TenantID:    e.TenantID,
		AgentID:     e.AgentID,
		TimestampUs: e.Timestamp,
		IngestedAt:  e.IngestedAt,
		EventType:   e.EventType,
		Severity:    int32(e.Severity),
		ProcessName: e.ProcessName,
		Cmdline:     e.Cmdline,
		ParentPID:   int32(e.ParentPID),
		SHA256:      e.SHA256,
		DestIP:      e.DestIP,
		SrcIP:       e.SrcIP,
		UserName:    e.UserName,
		Hostname:    e.Hostname,
		DataRaw:     e.DataRaw,
	}
}

func parquetCompression(codec string) compress.Codec {
	switch codec {
	case "snappy":
		return &pqsnappy.Codec{}
	case "gzip":
		return &pqgzip.Codec{}
	case "lz4raw", "lz4":
		return &pqlz4.Codec{}
	case "brotli":
		return &pqbrotli.Codec{}
	case "uncompressed", "none":
		return nil
	default:
		return &pqzstd.Codec{}
	}
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func uncompressedSize(events []TraceEventParquet) int64 {
	var size int64
	for _, e := range events {
		size += int64(len(e.ID) + len(e.TenantID) + len(e.AgentID) + 8 + 8 +
			len(e.EventType) + 4 +
			len(e.ProcessName) + len(e.Cmdline) + 4 +
			len(e.SHA256) + len(e.DestIP) + len(e.SrcIP) +
			len(e.UserName) + len(e.Hostname) + len(e.DataRaw))
	}
	return size
}
