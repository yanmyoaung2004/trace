package backup

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BackupDatabase creates a consistent backup of a SQLite database using VACUUM INTO.
// This works with WAL mode and doesn't block concurrent reads.
func BackupDatabase(db *sql.DB, dbPath, backupDir string, maxBackups int) (string, error) {
	os.MkdirAll(backupDir, 0700)

	ts := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("trace-db-%s.sqlite", ts)
	backupPath := filepath.Join(backupDir, name)

	// Use VACUUM INTO for safe online backup
	_, err := db.Exec(fmt.Sprintf(`VACUUM INTO '%s'`, backupPath))
	if err != nil {
		return "", fmt.Errorf("vacuum into: %w", err)
	}

	log.Printf("[backup] database backed up: %s (%d bytes)", backupPath, fileSize(backupPath))

	// Rotate old backups: only trace-db-*.sqlite files are eligible.
	// Never delete foreign files sharing the backup dir.
	if maxBackups > 0 {
		rotateDatabaseBackups(backupDir, maxBackups)
	}

	return backupPath, nil
}

// rotateDatabaseBackups prunes oldest trace-db-*.sqlite files beyond max.
func rotateDatabaseBackups(backupDir string, maxBackups int) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return
	}
	var backups []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if !strings.HasPrefix(name, "trace-db-") || !strings.HasSuffix(name, ".sqlite") {
			continue
		}
		backups = append(backups, name)
	}
	sort.Strings(backups) // timestamped names sort oldest-first
	for len(backups) > maxBackups {
		oldest := backups[0]
		backups = backups[1:]
		if err := os.Remove(filepath.Join(backupDir, oldest)); err != nil {
			log.Printf("[backup] prune %s: %v (keeping remainder)", oldest, err)
			break
		}
	}
}
