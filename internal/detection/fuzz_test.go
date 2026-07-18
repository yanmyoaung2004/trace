package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzYaraScanData(f *testing.F) {
	seeds := [][]byte{
		[]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
		[]byte("hello world"),
		{0x00, 0x01, 0x02},
		[]byte("normal log entry: user admin logged in from 10.0.0.1"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		scanner := NewYaraScanner()
		scanner.LoadEmbedded()
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.bin")
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Skip(err)
		}
		matches, err := scanner.ScanFile(path)
		if err != nil {
			return
		}
		for _, m := range matches {
			if m.Rule == "" {
				t.Error("match with empty rule name")
			}
		}
	})
}
