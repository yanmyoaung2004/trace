# Benchmarks

Run: `go test ./... -bench=. -benchmem -count=1`

Platform: Windows, amd64, Go 1.26.4

---

## Detection Agent

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
