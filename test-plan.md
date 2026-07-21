# Trace — Full Feature Test Plan

Instructions: run each test, note PASS/FAIL. For FAIL, fix before moving on.

---

## 1. Version & Help

```powershell
./trace version            # expect: Trace v0.1.1
./trace --help             # expect: list of all commands
```

---

## 2. Interactive TUI

```powershell
./trace                    # expect: full-screen TUI launches
```

| Action                           | Expected                                                          |
| -------------------------------- | ----------------------------------------------------------------- |
| Tab / Shift+Tab                  | Switch between Dashboard / Investigations / Cases / SIEM / Config |
| ↓ then Enter on an investigation | Shows investigation detail                                        |
| Esc                              | Go back from detail                                               |
| Press 2                          | Filter investigations by "running" status                         |
| Press q                          | Quit TUI                                                          |

---

## 3. Interactive Prompts

### 3a. trace investigate (interactive)

```powershell
# In a terminal (not piped), run:
./trace investigate
```

Expected: prompts for query, then lists playbooks to select from.

### 3b. trace case (interactive)

```powershell
./trace case
```

Expected: menu with List / Create / View / Back.

Select **Create Case**, enter a title, pick severity → expect "Case created: ..."

Then run `./trace case list` to verify the case exists.

### 3c. trace hunt (interactive)

```powershell
./trace hunt
```

Expected: menu with List / Run / Create / Back.

---

## 4. Manual Investigations

```powershell
# By natural language
./trace investigate "check hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# Expected: intent classified, playbook runs, report printed

# By explicit playbook
./trace investigate --playbook cve-lookup --param cve=CVE-2021-44228
# Expected: CVE lookup runs, report printed

# With file analysis
./trace investigate --playbook file-analysis --param path=C:\Windows\System32\notepad.exe
# Expected: YARA scan + hash lookup + PE metadata
```

---

## 5. Prefix ID Lookup

```powershell
./trace st 937f28a2        # expect: investigation details (using 8-char prefix)
./trace report 937f28a2    # expect: full investigation report
```

---

## 6. History & Status

```powershell
./trace hist               # expect: table of recent investigations
./trace hist -n 5          # expect: only 5 results
./trace status <full-id>   # expect: single investigation details
```

---

## 7. Shell Completions

```powershell
./trace completion powershell | Out-String | Invoke-Expression
# Then try:
./trace investigate --playbook [TAB]  # expect: lists playbook names
./trace case view [TAB]               # expect: lists case IDs (if any cases exist)
./trace case create --severity [TAB]  # expect: low/medium/high/critical
./trace hunt run [TAB]               # expect: lists hunt names (if any hunts exist)
```

---

## 8. Aliases

```powershell
./trace inv --help         # expect: same as "trace investigate --help"
./trace st --help          # expect: same as "trace status --help"
./trace hist --help        # expect: same as "trace history --help"
```

---

## 9. SIEM Engine (log file monitoring)

### 9a. Start SIEM

Kill any old `trace serve` process first.

```powershell
# Create test log
@"
<34>Jul 21 18:00:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
<34>Jul 21 18:00:01 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
<34>Jul 21 18:00:02 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
<34>Jul 21 18:00:03 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
<34>Jul 21 18:00:04 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2
"@ | Out-File -FilePath D:\Test\auth.log -Encoding ASCII

# Start SIEM
./trace serve --siem --log-dir "D:\Test" --syslog-addr :514
```

Expected: within 10-15s, alerts fire and investigations complete.
Verify: `./trace hist` shows new investigations.

### 9b. Append to log (real-time tailing)

```powershell
Add-Content -Path D:\Test\auth.log -Value "<34>Jul 21 18:01:00 myserver sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2"
```

Expected: new alert within 5-10s.

### 9c. Syslog (if you have a syslog sender)

```powershell
# From another machine, send syslog to this machine's port 514
# Or test locally with PowerShell UDP socket
```

---

## 10. Case Management

```powershell
# Create a case
./trace case create --title "Test phishing case" --severity high
# Expected: "Case created: ..."

# List cases
./trace case list
# Expected: shows the case

# View case details
./trace case view <case-id-prefix>
# Expected: case details with empty timeline

# Add a note
./trace case note <case-id-prefix> "Initial analysis complete"
# Expected: note added

# Add an IOC
./trace case ioc <case-id-prefix> --type ip --value 10.0.0.5
# Expected: IOC added

# Export as JSON
./trace case export <case-id-prefix>
# Expected: JSON output with case data

# Export as PDF
./trace case export-pdf <case-id-prefix> -o test-case.pdf
# Expected: PDF file created

# Close the case
./trace case close <case-id-prefix> --resolution "test complete"
# Expected: case closed

# Verify
./trace case list --status resolved
# Expected: case shows as closed
```

---

## 11. Evidence Attachments

```powershell
./trace case evidence <case-id> --file C:\Windows\System32\notepad.exe --name notepad-sample.exe
# Expected: "Evidence attached: notepad-sample.exe"
```

---

## 12. Automated Threat Hunting

```powershell
# List default hunts
./trace hunt list
# Expected: shows known-malware-scan, compliance-audit, rootkit-sweep, k8s-audit

# Run a hunt manually
./trace hunt run known-malware-scan
# Expected: hunt executes, investigation created

# Create a custom hunt
./trace hunt create --name test-hunt --playbook hash-lookup --schedule 24h
# Expected: "Hunt 'test-hunt' created"

# Pause and resume
./trace hunt pause test-hunt
./trace hunt resume test-hunt

# Delete
./trace hunt delete test-hunt
```

---

## 13. EDR Remote Actions

```powershell
# These require EDR credentials in config. Test with --help only:
./trace investigate --playbook edr-isolate --param hostname=test-pc
./trace investigate --playbook edr-scan --param hostname=test-pc
./trace investigate --playbook edr-kill-process --param hostname=test-pc --param pid=1234
```

Without EDR keys: expect error about missing config. With keys: expect API call + result.

---

## 14. Kubernetes Security

```powershell
# Ingest sample K8s audit log
Get-Content internal/siem/testdata/k8s-privileged-pod.json | Out-File D:\Test\k8s.log -Encoding ASCII
```

With SIEM watching `D:\Test`: expect K8s alerts within 15s.

---

## 15. Central Server Mode

```powershell
# Terminal 1: Start server
./trace server --http-addr :8080
# Expected: "Server started on :8080"

# Terminal 2: Open browser to http://localhost:8080
# Expected: dashboard shows investigations (from earlier SIEM runs)

# Terminal 3: Run an edge investigation that syncs
./trace serve --server-addr http://localhost:8080
```

---

## 16. Approval (HITL)

```powershell
./trace approval pending     # expect: empty or pending list
# Requires a playbook with wait: analyst_approval to test fully
```

---

## 17. Update & Plugin

```powershell
./trace update --help
./trace plugin list
```

---

## 18. Init Wizard

```powershell
# Run non-interactively to see prompts:
echo "" | ./trace init
# Expected: shows setup prompts
```

---

## Summary Table

| #   | Feature               | Status | Notes |
| --- | --------------------- | ------ | ----- |
| 1   | Version & Help        |        |       |
| 2   | Interactive TUI       |        |       |
| 3   | Interactive Prompts   |        |       |
| 4   | Manual Investigations |        |       |
| 5   | Prefix ID Lookup      |        |       |
| 6   | History & Status      |        |       |
| 7   | Shell Completions     |        |       |
| 8   | Aliases               |        |       |
| 9   | SIEM Engine           |        |       |
| 10  | Case Management       |        |       |
| 11  | Evidence Attachments  |        |       |
| 12  | Threat Hunting        |        |       |
| 13  | EDR Remote Actions    |        |       |
| 14  | Kubernetes Security   |        |       |
| 15  | Central Server        |        |       |
| 16  | HITL Approval         |        |       |
| 17  | Update & Plugin       |        |       |
| 18  | Init Wizard           |        |       |
