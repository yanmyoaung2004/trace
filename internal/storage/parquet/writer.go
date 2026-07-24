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

	"github.com/xitongsys/parquet-go/writer"
	"github.com/yanmyoaung2004/trace/internal/storage"
)

// ParquetWriter writes events to Parquet v2 files with ZSTD compression.
// It implements the "write to temp → fsync → atomic rename → manifest commit" pattern.
type ParquetWriter struct {
	opts        ParquetOptions
	tempDir     string
	outputDir   string
	accumulated []TraceEventParquet
	targetSize  int64 // target uncompressed file size
}

// NewParquetWriter creates a Parquet writer.
// tempDir is where temp files are written before atomic rename to outputDir.
func NewParquetWriter(tempDir, outputDir string, opts ParquetOptions) *ParquetWriter {
	if opts.RowGroupSize <= 0 {
		opts.RowGroupSize = 1_000_000
	}
	targetSize := int64(256 << 20) // 256MB default
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
//
// The write pattern:
//  1. Write to temp path
//  2. Compute SHA-256
//  3. Atomic rename to final path
//  4. Return FileResult for manifest commit
func (w *ParquetWriter) WriteBatch(ctx context.Context, events []*storage.Event, partitionKey string) (*storage.FileResult, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("empty batch")
	}

	// Convert to Parquet structs
	parqEvents := make([]TraceEventParquet, len(events))
	for i, e := range events {
		parqEvents[i] = eventToParquet(e)
	}

	// Sort by (agent_id, timestamp) for optimal compression
	sort.Slice(parqEvents, func(i, j int) bool {
		if parqEvents[i].AgentID != parqEvents[j].AgentID {
			return parqEvents[i].AgentID < parqEvents[j].AgentID
		}
		return parqEvents[i].TimestampUs < parqEvents[j].TimestampUs
	})

	// Generate temp path and final path
	ts := time.Now().UnixMicro()
	fileName := fmt.Sprintf("part-%s.parquet", fmt.Sprintf("%x", ts))
	tempPath := filepath.Join(w.tempDir, fileName+"."+fmt.Sprintf("%d", os.Getpid()))
	finalPath := filepath.Join(w.outputDir, partitionKey, fileName)

	if err := os.MkdirAll(filepath.Dir(finalPath), 0700); err != nil {
		return nil, fmt.Errorf("output dir: %w", err)
	}

	os.MkdirAll(w.tempDir, 0700)

	// Write Parquet file
	fw, err := os.Create(tempPath)
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}

	pw, err := writer.NewParquetWriterFromWriter(fw, &TraceEventParquet{}, int64(w.opts.RowGroupSize))
	if err != nil {
		fw.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("new parquet writer: %w", err)
	}

	pw.CompressionType = ToParquetCompression(w.opts.Compression)

	for i := range parqEvents {
		if err := pw.Write(parqEvents[i]); err != nil {
			pw.WriteStop()
			fw.Close()
			os.Remove(tempPath)
			return nil, fmt.Errorf("write event %d: %w", i, err)
		}
	}

	if err := pw.WriteStop(); err != nil {
		fw.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("write stop: %w", err)
	}

	if err := fw.Sync(); err != nil {
		fw.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("fsync: %w", err)
	}
	fw.Close()

	// Compute SHA-256
	hash, err := fileSHA256(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("sha256: %w", err)
	}

	// Read file info
	info, err := os.Stat(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("stat: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, finalPath); err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("rename: %w", err)
	}

	// Gather min/max IDs and timestamps
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

// eventToParquet converts a storage.Event to a Parquet-compatible struct.
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

// fileSHA256 computes the SHA-256 hash of a file.
func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// uncompressedSize estimates the uncompressed size of the event batch.
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

// Close releases any resources held by the writer.
func (w *ParquetWriter) Close() error {
	w.accumulated = nil
	return nil
}
