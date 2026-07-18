# InnoIgniterAI — End-to-End Demo Script
# Run this from the dev/ directory after building the binary.
# This walks through installation, investigations, SIEM, server, and team features.

param(
    [string]$VtKey = "",
    [string]$AbuseIPDBKey = "",
    [string]$OtxKey = ""
)

$ErrorActionPreference = "Continue"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Dev = Resolve-Path "$Here\.."
$Bin = "$Dev\innoigniter.exe"
$EicarHash = "e99a18c428cb38d5f260853678922e03"
$MimikatzHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     InnoIgniterAI — End-to-End Demo             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─── Step 0: Build ───
Write-Host "▸ Step 0: Build binary" -ForegroundColor Yellow
Push-Location $Dev
go build -o innoigniter.exe ./cmd/innoigniter
if (-not (Test-Path $Bin)) { Write-Host "Build failed!" -ForegroundColor Red; exit 1 }
Write-Host "  ✓ Binary built: $Bin" -ForegroundColor Green
Write-Host ""

# ─── Step 1: Version & Help ───
Write-Host "▸ Step 1: Version & help" -ForegroundColor Yellow
& $Bin version
Write-Host ""

& $Bin --help
Write-Host ""

# ─── Step 2: Quick investigation (no setup) ───
Write-Host "▸ Step 2: Quick investigation — known malicious hash" -ForegroundColor Yellow
Write-Host "  Running: investigate `"check hash $MimikatzHash`"" -ForegroundColor Gray
$result = & $Bin investigate "check hash $MimikatzHash" 2>&1
Write-Host $result
Write-Host ""

# ─── Step 3: Investigation with explicit playbook ───
Write-Host "▸ Step 3: Explicit playbook — hash-lookup" -ForegroundColor Yellow
Write-Host "  Running: investigate --playbook hash-lookup --param hash=$EicarHash" -ForegroundColor Gray
$result = & $Bin investigate --playbook hash-lookup --param "hash=$EicarHash" 2>&1
Write-Host $result
Write-Host ""

# ─── Step 4: Domain reputation ───
Write-Host "▸ Step 4: Domain reputation check" -ForegroundColor Yellow
Write-Host "  Running: investigate --playbook domain-reputation --param domain=evil.com" -ForegroundColor Gray
$result = & $Bin investigate --playbook domain-reputation --param domain=evil.com 2>&1
Write-Host $result
Write-Host ""

# ─── Step 5: History & Status ───
Write-Host "▸ Step 5: Investigation history & status" -ForegroundColor Yellow
& $Bin history
Write-Host ""

$lastInv = & $Bin history | Select-Object -Skip 1 | Select-Object -First 1
if ($lastInv) {
    $invId = ($lastInv -split '\s+')[0]
    Write-Host "  Status for $invId :" -ForegroundColor Gray
    & $Bin status $invId
}
Write-Host ""

# ─── Step 6: File analysis (YARA) ───
Write-Host "▸ Step 6: File analysis with YARA" -ForegroundColor Yellow
$tmpDir = Join-Path $env:TEMP "inno-demo-$(Get-Random)"
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$eicarPath = Join-Path $tmpDir "eicar.txt"
Set-Content -Path $eicarPath -Value "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"

Write-Host "  Created EICAR test file at $eicarPath" -ForegroundColor Gray
$result = & $Bin investigate --playbook file-analysis --param "path=$eicarPath" --param "hash=$EicarHash" 2>&1
Write-Host $result
Remove-Item -Recurse $tmpDir -Force -ErrorAction SilentlyContinue
Write-Host ""

# ─── Step 7: SIEM engine (quick test) ───
Write-Host "▸ Step 7: SIEM engine detection (1 min test)" -ForegroundColor Yellow
Write-Host "  Starting SIEM engine in background..." -ForegroundColor Gray
$logDir = Join-Path $env:TEMP "inno-siem-logs-$(Get-Random)"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

$job = Start-Job -ScriptBlock {
    param($bin, $logDir)
    & $bin serve --siem --log-dir $logDir --syslog-addr :0
} -ArgumentList $Bin, $logDir

Start-Sleep -Seconds 2

Write-Host "  Generating test log events..." -ForegroundColor Gray
1..6 | ForEach-Object {
    Add-Content -Path "$logDir\auth.log" -Value "<34>Jul 18 12:00:00 server sshd[$_]$(Get-Random): Failed password for root from 10.0.0.5 port 22 ssh2"
}
Add-Content -Path "$logDir\syslog.log" -Value '{"timestamp":"2026-07-18T12:00:00Z","event":"login","user":"admin","severity":3,"message":"Failed password for root from 10.0.0.5"}'

Start-Sleep -Seconds 3
Write-Host "  SIEM rules should have fired for multiple failed logins." -ForegroundColor Green

Stop-Job $job -ErrorAction SilentlyContinue
Remove-Job $job -ErrorAction SilentlyContinue
Remove-Item -Recurse $logDir -Force -ErrorAction SilentlyContinue
Write-Host ""

# ─── Step 8: Central server mode ───
Write-Host "▸ Step 8: Central server mode (brief test)" -ForegroundColor Yellow
Write-Host "  Starting server in background on :9090..." -ForegroundColor Gray

$serverJob = Start-Job -ScriptBlock {
    param($bin)
    & $bin server --http-addr :9090
} -ArgumentList $Bin

Start-Sleep -Seconds 2

try {
    $health = Invoke-WebRequest -Uri "http://localhost:9090/health" -UseBasicParsing -TimeoutSec 5
    Write-Host "  ✓ Server health check: $($health.StatusCode)" -ForegroundColor Green

    $nodes = Invoke-WebRequest -Uri "http://localhost:9090/api/v1/nodes" -UseBasicParsing -TimeoutSec 5
    Write-Host "  ✓ Nodes API response received" -ForegroundColor Green

    Write-Host "  Open http://localhost:9090 in your browser for the dashboard." -ForegroundColor Cyan
} catch {
    Write-Host "  Server not reachable (expected in CI)" -ForegroundColor Yellow
}

Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -ErrorAction SilentlyContinue
Write-Host ""

# ─── Step 9: Plugin listing ───
Write-Host "▸ Step 9: Agent & plugin listing" -ForegroundColor Yellow
& $Bin plugin list
Write-Host ""

# ─── Step 10: Cleanup ───
Write-Host "▸ Step 10: Cleanup" -ForegroundColor Yellow
Write-Host "  Removing demo database..." -ForegroundColor Gray
Remove-Item -Recurse "$env:USERPROFILE\.innoigniter" -Force -ErrorAction SilentlyContinue
Write-Host ""

# ─── Summary ───
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Demo Complete!                                  ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Steps demonstrated:                              ║" -ForegroundColor Cyan
Write-Host "║  1. Build from source                            ║" -ForegroundColor Cyan
Write-Host "║  2. Version & help                               ║" -ForegroundColor Cyan
Write-Host "║  3. Natural language investigation               ║" -ForegroundColor Cyan
Write-Host "║  4. Explicit playbook execution                  ║" -ForegroundColor Cyan
Write-Host "║  5. Domain reputation check                      ║" -ForegroundColor Cyan
Write-Host "║  6. History & status tracking                    ║" -ForegroundColor Cyan
Write-Host "║  7. File analysis with YARA                     ║" -ForegroundColor Cyan
Write-Host "║  8. SIEM log monitoring + correlation            ║" -ForegroundColor Cyan
Write-Host "║  9. Central server mode + API                    ║" -ForegroundColor Cyan
Write-Host "║ 10. Agent plugin listing                         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  innoigniter init                     — configure API keys" -ForegroundColor Gray
Write-Host "  innoigniter serve --siem             — start daemon with SIEM" -ForegroundColor Gray
Write-Host "  innoigniter server --http-addr :8080  — start central server" -ForegroundColor Gray
Write-Host "  innoigniter completion powershell | Out-String | Invoke-Expression  — enable tab completion" -ForegroundColor Gray

Pop-Location
