# Benchmarks

Run: `go test ./... -bench=. -benchmem -count=1`

Platform: Windows, amd64, Go 1.26.4

---

## Sift Agent

| Benchmark | Iterations | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| YaraScan_EICAR | 18,819 | 61,100 | 3,770 | 47 |
| YaraScan_CleanFile | 19,047 | 67,776 | 2,858 | 42 |
| HashLookup_Known | 34,444 | 32,917 | 1,936 | 38 |
| HashLookup_Unknown | 54,172 | 20,879 | 1,040 | 23 |
| PEAnalyze_NotPE | 16,315 | 65,269 | 2,211 | 23 |

## SIEM Decoders

| Benchmark | Iterations | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| JSONDecoder | 287,235 | 4,022 | 944 | 27 |
| ApacheDecoder | 287,086 | 3,859 | 920 | 14 |
| ApacheDecoder_Error | 312,133 | 3,617 | 905 | 14 |
| SyslogDecoder | 307,389 | 3,543 | 1,105 | 17 |
| AutoDecoder_JSON | 452,244 | 2,741 | 848 | 20 |
| AutoDecoder_Syslog | 222,102 | 5,579 | 1,497 | 26 |
| AutoDecoder_Apache | 273,633 | 4,545 | 1,238 | 22 |
| WindowsEventDecoder | 6,199,101 | 212 | 16 | 1 |

---

## YARA Rules

Scans a file against embedded rules (EICAR, PowerShell, Base64,
packed binaries, Mimikatz, CobaltStrike, process injection).

Clean file scan is slightly slower than EICAR because all rules
are evaluated fully (EICAR matches early in the rule set).

## Hash Lookup

Known hashes (Mimikatz, EICAR) are cached in SQLite via WAL mode.
Unknown hashes complete faster because no VT API call is attempted
(no key configured in benchmarks).

## SIEM Decoders

Windows Event decoder is the fastest at 212ns — simple CSV split.
Auto Decoder probes format detection first, adding ~1-2µs overhead.
All decoders are heap-allocated (no zero-allocation path).

---

## EDR Agent

| Benchmark | Iterations | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| YaraMatcher (5 samples, 17 rules) | 2,300 | 525,000 | 192 | 2 |
| Deduplicator (1k unique + 1k dup) | — | verified pass | — | — |
| FloodDetector (1k events) | — | verified pass | — | — |

### YARA Matcher

Matches 5 sample types (EICAR, Mimikatz, CobaltStrike, PowerShell encoded, benign)
against 17 built-in rules + external .yar loader. Pure-Go implementation with
zero C dependencies. ~1,900 ops/sec, 2 allocations per scan.

### On-Agent Rules

| Rule | Type | Trigger |
|------|------|---------|
| EICAR_Test | String match | Standard AV test file |
| Suspicious_PowerShell | Regex | Base64 encoded PS, IEX, DownloadString |
| Suspicious_CMD | Regex | cmd /c curl/wget/bitsadmin |
| Base64_Encoded_Strings | Regex | Long base64 sequences |
| Suspicious_Entropy | Entropy >7.0 | Packed/encrypted binaries |
| Packed_Binary | PE section check | UPX, packed sections |
| Suspicious_Imports | Regex | CreateRemoteThread, VirtualAllocEx |
| Process_Injection_API | Regex | CreateRemoteThread + WriteProcessMemory |
| Keylogger_Indicators | Regex | SetWindowsHookEx, GetAsyncKeyState |
| Ransomware_Indicators | Regex | vssadmin, bcdedit, wevtutil |
| VM_Escape_Indicators | Regex | IsDebuggerPresent, VMCheck |
| Mimikatz_Strings | Regex | sekurlsa, lsadump, wdigest |
| CobaltStrike_Beacon | Regex | beacon.dll, reflective_loader |
| XOR_Encoded_Payload | Byte analysis | Single/multi-byte XOR, ADD/SUB/ROL |
| Packed_PE_Binary | PE structure | Section entropy + EP analysis |

External `.yar` files loaded from `~/.trace-agent/yara/` at startup.
