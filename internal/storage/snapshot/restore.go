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
	"strings"
)

// Restore extracts a tar.gz snapshot into the given directory.
func Restore(ctx context.Context, inputPath, dataDir string) error {
	entries, err := DryRun(ctx, inputPath)
	if err != nil {
		return err
	}
	log.Printf("[snapshot] restoring %d entries: %s -> %s", len(entries), inputPath, dataDir)

	fr, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer fr.Close()

	gr, err := gzip.NewReader(fr)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		// ZipSlip guard: entries must stay inside dataDir.
		target, err := resolveTarget(dataDir, header.Name)
		if err != nil {
			return err
		}
		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0700)
			continue
		}

		os.MkdirAll(filepath.Dir(target), 0700)

		fw, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("create %s: %w", target, err)
		}

		if _, err := io.Copy(fw, tr); err != nil {
			fw.Close()
			return fmt.Errorf("write %s: %w", target, err)
		}
		if err := fw.Sync(); err != nil {
			fw.Close()
			return fmt.Errorf("fsync %s: %w", target, err)
		}
		fw.Close()
	}

	log.Printf("[snapshot] restored to %s", dataDir)
	return nil
}

// DryRun lists snapshot entries without extracting (pre-restore inspection).
func DryRun(ctx context.Context, inputPath string) ([]string, error) {
	fr, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer fr.Close()

	gr, err := gzip.NewReader(fr)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var entries []string
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		entries = append(entries, fmt.Sprintf("%s (%d bytes)", header.Name, header.Size))
	}
	return entries, nil
}

// resolveTarget confines an archive entry inside dataDir (ZipSlip guard).
func resolveTarget(dataDir, name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing traversal entry: %q", name)
	}
	target := filepath.Join(dataDir, clean)
	rel, err := filepath.Rel(dataDir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing escaping entry: %q", name)
	}
	return target, nil
}
