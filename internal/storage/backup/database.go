package backup

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	// Rotate old backups
	if maxBackups > 0 {
		entries, err := os.ReadDir(backupDir)
		if err == nil {
			var backups []string
			for _, e := range entries {
				if !e.IsDir() {
					backups = append(backups, e.Name())
				}
			}
			for len(backups) > maxBackups {
				oldest := backups[0]
				backups = backups[1:]
				os.Remove(filepath.Join(backupDir, oldest))
			}
		}
	}

	return backupPath, nil
}
