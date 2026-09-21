package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
	_ "modernc.org/sqlite"
)

// Create exports the full TSE state to a tar.gz archive.
// Consistency (R12): checkpoint hot.db (TRUNCATE) first, copy db+wal+shm as a
// set, verify the manifest, and stream everything to a temp file that is
// atomically renamed into place. No whole-file buffering.
func Create(ctx context.Context, outputPath, dataDir string, f *flusher.Flusher, m *manifestpkg.Manifest) error {
	log.Printf("[snapshot] creating snapshot: %s", outputPath)

	// 1. Checkpoint so the db file is self-consistent; wal+shm are still
	// archived for crash-window coverage.
	checkpointHot(dataDir)

	// 2. Manifest verify before archiving (fail-closed: never snapshot an
	// unreadable manifest).
	if m != nil {
		if _, err := m.FilesFor(ctx, "", 0, 0, "committed"); err != nil {
			return fmt.Errorf("manifest verify: %w", err)
		}
		if _, err := m.Watermark(ctx); err != nil {
			return fmt.Errorf("watermark verify: %w", err)
		}
	}

	// 3. Stream to a unique temp file, then atomic rename.
	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.tmp-%s", outputPath, hex.EncodeToString(rb[:]))
	fw, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpPath)
		}
	}()

	gw := gzip.NewWriter(fw)
	tw := tar.NewWriter(gw)

	fail := func(format string, args ...any) error {
		tw.Close()
		gw.Close()
		fw.Close()
		return fmt.Errorf(format, args...)
	}

	// Add manifest + hot store (db+wal+shm as a set; missing wal/shm skipped).
	for _, name := range []string{"manifest.db", "hot.db", "hot.db-wal", "hot.db-shm"} {
		if err := addFile(tw, filepath.Join(dataDir, name), name); err != nil {
			return fail("%s: %w", name, err)
		}
	}

	// Add Parquet files (streamed, no whole-file buffering).
	if err := filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".parquet" {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		relPath, _ := filepath.Rel(dataDir, path)
		return addFile(tw, path, relPath)
	}); err != nil {
		return fail("walk: %w", err)
	}

	if err := tw.Close(); err != nil {
		gw.Close()
		fw.Close()
		return fmt.Errorf("tar close: %w", err)
	}
	if err := gw.Close(); err != nil {
		fw.Close()
		return fmt.Errorf("gzip close: %w", err)
	}
	if err := fw.Sync(); err != nil {
		fw.Close()
		return fmt.Errorf("fsync: %w", err)
	}
	fw.Close()

	cleanup = false
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	log.Printf("[snapshot] created: %s", outputPath)
	return nil
}

// checkpointHot runs a TRUNCATE checkpoint on a scratch connection so the
// archived db file is self-consistent (R12). Best-effort: logs and continues
// when the live store is busy.
func checkpointHot(dataDir string) {
	dbPath := filepath.Join(dataDir, "hot.db")
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return
	}
	defer db.Close()
	var busy, logPages, ckpt int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logPages, &ckpt); err != nil {
		log.Printf("[snapshot] checkpoint: %v", err)
	}
}

// addFile adds a single file to the tar archive, streaming its contents.
// Missing files are skipped (wal/shm may not exist when idle).
func addFile(tw *tar.Writer, srcPath, arcPath string) error {
	info, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // skip missing files
		}
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = arcPath

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	return err
}
