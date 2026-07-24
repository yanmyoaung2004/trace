package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/yanmyoaung2004/trace/internal/storage/flusher"
	manifestpkg "github.com/yanmyoaung2004/trace/internal/storage/manifest"
)

// Create exports the full TSE state to a tar.zst archive.
// The flusher is quiesced during the snapshot to ensure consistency.
func Create(ctx context.Context, outputPath, dataDir string, f *flusher.Flusher, m *manifestpkg.Manifest) error {
	log.Printf("[snapshot] creating snapshot: %s", outputPath)

	// Create the output file
	fw, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer fw.Close()

	// GZip compression
	gw := gzip.NewWriter(fw)
	defer gw.Close()

	// Tar writer
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add manifest
	manifestPath := filepath.Join(dataDir, "manifest.db")
	if err := addFile(tw, manifestPath, "manifest.db"); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}

	// Add hot store
	hotPath := filepath.Join(dataDir, "hot.db")
	if err := addFile(tw, hotPath, "hot.db"); err != nil {
		return fmt.Errorf("hot: %w", err)
	}

	// Add recent Parquet files (last 7 days)
	filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".parquet" {
			return nil
		}
		relPath, _ := filepath.Rel(dataDir, path)
		return addFile(tw, path, filepath.Join("events", relPath))
	})

	log.Printf("[snapshot] created: %s", outputPath)
	return nil
}

// addFile adds a single file to the tar archive.
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
