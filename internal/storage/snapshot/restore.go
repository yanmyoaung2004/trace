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
)

// Restore extracts a tar.zst snapshot into the given directory.
func Restore(ctx context.Context, inputPath, dataDir string) error {
	log.Printf("[snapshot] restoring: %s -> %s", inputPath, dataDir)

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
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		target := filepath.Join(dataDir, header.Name)
		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0700)
			continue
		}

		os.MkdirAll(filepath.Dir(target), 0700)

		fw, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("create %s: %w", target, err)
		}

		if _, err := io.Copy(fw, tr); err != nil {
			fw.Close()
			return fmt.Errorf("write %s: %w", target, err)
		}
		fw.Close()
	}

	log.Printf("[snapshot] restored to %s", dataDir)
	return nil
}
