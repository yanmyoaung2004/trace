package monitor

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
)

type YaraRule struct {
	Name        string
	Description string
	Severity    Severity
	Matcher     yaraMatch
}

func (r *YaraRule) Matches(data []byte) bool {
	return r.Matcher.Matches(data)
}

type yaraMatch interface {
	Matches(data []byte) bool
}

type yaraString struct {
	pattern []byte
}

func (y yaraString) Matches(data []byte) bool {
	return bytes.Contains(data, y.pattern)
}

type yaraRegex struct {
	pattern *regexp.Regexp
}

func (y yaraRegex) Matches(data []byte) bool {
	return y.pattern.Match(data)
}

type yaraEntropy struct {
	threshold float64
}

func (y yaraEntropy) Matches(data []byte) bool {
	if len(data) < 256 {
		return false
	}
	return calculateEntropy(data) > y.threshold
}

type yaraPENotSection struct{}

type xorEncoded struct{}

func (xorEncoded) Matches(data []byte) bool { return detectXOR(data) }

type packedPE struct{}

func (packedPE) Matches(data []byte) bool {
	pe := AnalyzePE(data)
	return pe.IsPE && pe.IsPacked
}

func (yaraPENotSection) Matches(data []byte) bool {
	if len(data) < 2 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	return true
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make(map[byte]float64)
	for _, b := range data {
		freq[b]++
	}
	var entropy float64
	for _, count := range freq {
		p := count / float64(len(data))
		if p > 0 {
			entropy -= p * log2(p)
		}
	}
	return entropy
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	const ln2 = 0.6931471805599453
	var n float64
	for x >= 2 {
		x /= 2
		n++
	}
	for x < 1 {
		x *= 2
		n--
	}
	return n + (x-1)/ln2
}

type YaraMatcher struct {
	rules []*YaraRule
}

func NewYaraMatcher() *YaraMatcher {
	return &YaraMatcher{
		rules: builtinYaraRules(),
	}
}

func (ym *YaraMatcher) MatchFile(path string) ([]*YaraRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ym.MatchBytes(data), nil
}

func (ym *YaraMatcher) MatchBytes(data []byte) []*YaraRule {
	var matches []*YaraRule
	for _, rule := range ym.rules {
		if rule.Matcher.Matches(data) {
			matches = append(matches, rule)
		}
	}
	return matches
}

func (ym *YaraMatcher) MatchProcess(pid int) ([]*YaraRule, error) {
	procPath := fmt.Sprintf("/proc/%d/exe", pid)
	_, err := os.Stat(procPath)
	if err != nil {
		return nil, err
	}
	return ym.MatchFile(procPath)
}

func detectXOR(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	nullPct := float64(countZeroBytes(data)) / float64(len(data))
	if nullPct > 0.4 {
		return false
	}

	if detectSingleByteXOR(data) {
		return true
	}
	if detectMultiByteXOR(data) {
		return true
	}
	if detectAddSubCipher(data) {
		return true
	}

	return false
}

func countZeroBytes(data []byte) int {
	c := 0
	for _, b := range data {
		if b == 0 {
			c++
		}
	}
	return c
}

func detectSingleByteXOR(data []byte) bool {
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}

	bestScore := 0
	for key := 0; key < 256; key++ {
		score := 0
		for _, b := range sample {
			d := b ^ byte(key)
			if d >= 0x20 && d <= 0x7E {
				score++
			}
			if d == ' ' || d == 'e' || d == 't' || d == 'a' {
				score += 2
			}
			if d == 0 {
				score -= 3
			}
		}
		if score > bestScore {
			bestScore = score
		}
	}

	return bestScore > len(sample)*70/100
}

func detectMultiByteXOR(data []byte) bool {
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}

	// Try key lengths 2-16
	for keyLen := 2; keyLen <= 16; keyLen++ {
		score := 0
		// Hamming distance between consecutive keyLen-sized blocks
		blocks := len(sample) / keyLen
		if blocks < 2 {
			continue
		}
		hamming := 0
		for b := 0; b < blocks-1 && b < 20; b++ {
			for i := 0; i < keyLen; i++ {
				a1 := sample[b*keyLen+i]
				a2 := sample[(b+1)*keyLen+i]
				// XOR to find bits that differ
				x := a1 ^ a2
				// Count bits
				for x > 0 {
					if x&1 == 1 {
						hamming++
					}
					x >>= 1
				}
			}
		}
		avgHamming := float64(hamming) / float64(min(blocks, 20))
		normalized := avgHamming / float64(keyLen)

		// Normalized Hamming distance ~ 0.5 means XOR with key length keyLen
		if normalized > 0.35 && normalized < 0.7 {
			score++
		}

		// Try to decrypt and check printable ratio
		for skip := 0; skip < keyLen; skip++ {
			printable := 0
			total := 0
			for i := skip; i < len(sample); i += keyLen {
				total++
				if sample[i] >= 0x20 && sample[i] <= 0x7E {
					printable++
				}
			}
			if total > 5 && float64(printable)/float64(total) > 0.75 {
				score++
			}
		}

		if score >= keyLen {
			return true
		}
	}
	return false
}

func detectAddSubCipher(data []byte) bool {
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}

	// Try ADD cipher: each byte = plaintext + key (mod 256)
	for key := 0; key < 256; key++ {
		score := 0
		for _, b := range sample {
			d := (b - byte(key)) & 0xFF
			if d >= 0x20 && d <= 0x7E {
				score++
			}
			if d == ' ' || d == 'e' {
				score += 2
			}
		}
		if score > len(sample)*60/100 {
			return true
		}
	}

	// Try SUB cipher: each byte = plaintext - key (mod 256)
	for key := 0; key < 256; key++ {
		score := 0
		for _, b := range sample {
			d := (b + byte(key)) & 0xFF
			if d >= 0x20 && d <= 0x7E {
				score++
			}
			if d == ' ' || d == 'e' {
				score += 2
			}
		}
		if score > len(sample)*60/100 {
			return true
		}
	}

	// Try ROL cipher: each byte rotated left by key bits
	for shift := 1; shift < 8; shift++ {
		score := 0
		for _, b := range sample {
			d := ((b << shift) | (b >> (8 - shift))) & 0xFF
			if d >= 0x20 && d <= 0x7E {
				score++
			}
		}
		if score > len(sample)*55/100 {
			return true
		}
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func builtinYaraRules() []*YaraRule {
	return []*YaraRule{
		{
			Name: "EICAR_Test", Description: "EICAR standard AV test file",
			Severity: SeverityInfo, Matcher: yaraString{[]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")},
		},
		{
			Name: "Suspicious_PowerShell", Description: "Suspicious PowerShell invocation",
			Severity: SeverityWarning,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(powershell.*-e\s+[a-z0-9]{50,}|-EncodedCommand|IEX\s*\(|Invoke-Expression|DownloadString\s*\()`)},
		},
		{
			Name: "Suspicious_CMD", Description: "Suspicious cmd.exe execution",
			Severity: SeverityWarning,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(cmd\.exe.*\/c\s+(curl|wget|bitsadmin|certutil|powershell)|\/c\s+ping\s+-n\s+1)`)},
		},
		{
			Name: "Base64_Encoded_Strings", Description: "High concentration of base64 data",
			Severity: SeverityWarning,
			Matcher:  yaraRegex{regexp.MustCompile(`(?:[A-Za-z0-9+/]{40,}={0,2})`)},
		},
		{
			Name: "Suspicious_Entropy", Description: "High entropy file (packed/encrypted)",
			Severity: SeverityWarning,
			Matcher:  yaraEntropy{threshold: 7.0},
		},
		{
			Name: "Packed_Binary", Description: "PE with unusual section entropy",
			Severity: SeverityWarning,
			Matcher:  yaraPENotSection{},
		},
		{
			Name: "Suspicious_Imports", Description: "Process injection API imports",
			Severity: SeverityWarning,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(CreateRemoteThread|WriteProcessMemory|VirtualAllocEx|OpenProcess|NtCreateThreadEx|QueueUserAPC|SetWindowsHookEx)`)},
		},
		{
			Name: "Process_Injection_API", Description: "Process injection indicators",
			Severity: SeverityAlert,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(CreateRemoteThread.*WriteProcessMemory|OpenProcess.*VirtualAllocEx)`)},
		},
		{
			Name: "Keylogger_Indicators", Description: "Keylogger API patterns",
			Severity: SeverityWarning,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(SetWindowsHookEx.*WH_KEYBOARD|GetAsyncKeyState|GetForegroundWindow|GetWindowText[AW])`)},
		},
		{
			Name: "Ransomware_Indicators", Description: "Ransomware-like behavior indicators",
			Severity: SeverityAlert,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(vssadmin.*delete.*shadows|bcdedit.*bootstatuspolicy|wevtutil.*cl\s+|cipher.*\/w:)`)},
		},
		{
			Name: "VM_Escape_Indicators", Description: "VM escape/sandbox detection",
			Severity: SeverityWarning,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(CheckRemoteDebuggerPresent|IsDebuggerPresent|NtQueryInformationProcess.*ProcessDebugPort|VMCheck|vbox|vmware)`)},
		},
		{
			Name: "Mimikatz_Strings", Description: "Mimikatz credential tool strings",
			Severity: SeverityAlert,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(mimikatz|sekurlsa|kerberos::|lsadump::|wdigest|cache::|dpapi::|vault::)`)},
		},
		{
			Name: "XOR_Encoded_Payload", Description: "XOR-encoded data detected",
			Severity: SeverityWarning,
			Matcher:  xorEncoded{},
		},
		{
			Name: "Packed_PE_Binary", Description: "PE binary with packer indicators",
			Severity: SeverityAlert,
			Matcher:  packedPE{},
		},
		{
			Name: "CobaltStrike_Beacon", Description: "Cobalt Strike beacon indicators",
			Severity: SeverityAlert,
			Matcher:  yaraRegex{regexp.MustCompile(`(?i)(cobaltstrike|beacon\.(dll|exe)|\.stage_[0-9a-f]{4}|msfstrip|reflective_loader)`)},
		},
	}
}

func (r *YaraRule) String() string {
	return fmt.Sprintf("%s (%s)", r.Name, r.Description)
}
