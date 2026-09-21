package monitor

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzYaraScanData feeds arbitrary bytes at the monitor YARA matcher. The
// matcher must never panic or hang; results only reference known rule names.
func FuzzYaraScanData(f *testing.F) {
	seeds := [][]byte{
		[]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
		[]byte("powershell -EncodedCommand aGVsbG8="),
		{0x00, 0x01, 0x02, 0x4d, 0x5a},
		[]byte("normal process: C:\\Windows\\System32\\notepad.exe"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		ym := NewYaraMatcher()
		for _, r := range ym.MatchBytes(data) {
			if r.Name == "" {
				t.Error("match with empty rule name")
			}
		}
	})
}

// FuzzYaraRuleFile feeds malformed rule files at the external rule parser.
// The parser must return nil rules (never panic) on garbage input.
func FuzzYaraRuleFile(f *testing.F) {
	seeds := []string{
		"rule Test { meta: description = \"t\" strings: $a = \"evil\" condition: $a }",
		"rule Broken { strings: ",
		"",
		"not a rule at all \x00\xff",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.yar")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Skip(err)
		}
		yl := NewYaraLoader()
		yl.SetExternalDir(dir)
		_, _ = yl.Load()
	})
}
