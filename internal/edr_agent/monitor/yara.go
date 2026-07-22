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
	scores := make(map[byte]int)
	var nullCount int
	for i, b := range data {
		if b == 0 {
			nullCount++
			continue
		}
		if i+1 < len(data) && data[i+1] != 0 {
			scores[data[i+1]^b]++
		}
	}
	nullPct := float64(nullCount) / float64(len(data))
	if nullPct > 0.4 {
		return false
	}
	for _, count := range scores {
		if count > 50 && count > len(data)/20 {
			return true
		}
	}
	return false
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
