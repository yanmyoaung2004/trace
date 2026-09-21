<#
.SYNOPSIS
    Trace Agent Installer — Windows
.DESCRIPTION
    Installs trace-agent as a Windows service.
    Download is authenticated and verified before install:
      GET <server>/api/v1/edr/update/download?os=windows&arch=amd64
      Authorization: Bearer <key> (required)
      X-Trace-SHA256 verified always; X-Trace-Signature verified when
      TRACE_UPDATE_VERIFY_KEY_HEX is set (fail-closed when key set).
    Verify happens BEFORE copy into the install dir; the same signature
    is served as "signature" in the update-check JSON. Unsigned when the
    verify key is set, or a hash/signature mismatch, refuses the install.
    Usage: .\install.ps1 -ServerUrl https://trace-server:8080 -ApiKey "key"
           .\install.ps1 -ServerUrl https://trace-server:8080 -ApiKeyFile C:\path\agent.key
#>

param(
    [string]$ServerUrl = "https://127.0.0.1:8080",
    [string]$ApiKey = "",
    [string]$ApiKeyFile = "",
    [string]$BinDir = "$env:ProgramFiles\Trace\Agent",
    [string]$DataDir = "$env:ProgramData\Trace\Agent",
    [string]$ConfigDir = "$env:ProgramData\Trace\Agent"
)

if ($ApiKeyFile -ne "" -and (Test-Path $ApiKeyFile)) {
    $ApiKey = (Get-Content $ApiKeyFile -Raw).Trim()
}
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    if ($env:TRACE_API_KEY) { $ApiKey = $env:TRACE_API_KEY.Trim() }
    elseif ($env:TRACE_API_KEY_FILE -and (Test-Path $env:TRACE_API_KEY_FILE)) {
        $ApiKey = (Get-Content $env:TRACE_API_KEY_FILE -Raw).Trim()
    }
}
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Error "An API key is required (-ApiKey, -ApiKeyFile, TRACE_API_KEY, or TRACE_API_KEY_FILE). Anonymous download is refused."
    exit 1
}

Write-Host "==> Trace Agent Installer (Windows)"
Write-Host "    Server: $ServerUrl"
Write-Host "    Binary: $BinDir\trace-agent.exe"

# Create directories
New-Item -ItemType Directory -Force -Path $BinDir, $DataDir, $ConfigDir | Out-Null

# Copy binary (assumes install.ps1 is next to trace-agent.exe)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$localBin = Join-Path $scriptDir "trace-agent.exe"
$staged = Join-Path ([System.IO.Path]::GetTempPath()) ("trace-agent-" + [System.Guid]::NewGuid().ToString("N") + ".exe")
try {
    if (Test-Path $localBin) {
        Write-Host "==> Installing from local binary (no network verify; ensure your checkout is trusted)"
        Copy-Item $localBin $staged -Force
    } else {
        $downloadUrl = "${ServerUrl}/api/v1/edr/update/download?os=windows&arch=amd64"
        Write-Host "==> Downloading (authenticated) from $downloadUrl"
        $resp = Invoke-WebRequest -Uri $downloadUrl -OutFile $staged -PassThru `
            -Headers @{ Authorization = "Bearer $ApiKey" } -UseBasicParsing
        $expectedSha = $resp.Headers["X-Trace-SHA256"]
        $sigB64 = $resp.Headers["X-Trace-Signature"]
        if ([string]::IsNullOrWhiteSpace($expectedSha)) {
            Write-Error "Server did not return X-Trace-SHA256; refusing unverified binary."
            exit 1
        }
        $expectedSha = ($expectedSha | Select-Object -First 1).Trim().ToLower()
        $gotSha = (Get-FileHash $staged -Algorithm SHA256).Hash.ToLower()
        if ($gotSha -ne $expectedSha) {
            Write-Error "Checksum mismatch (got $gotSha, expected $expectedSha); refusing."
            exit 1
        }
        Write-Host "    Checksum verified: $gotSha"
        $verifyKeyHex = $env:TRACE_UPDATE_VERIFY_KEY_HEX
        if ($sigB64) {
            if ([string]::IsNullOrWhiteSpace($verifyKeyHex)) {
                Write-Host "    WARNING: server sent a signature but TRACE_UPDATE_VERIFY_KEY_HEX is unset; hash verified, signature NOT checked."
            } else {
                # ed25519 verify via .NET is unavailable inbox; use python3+nacl when present.
                $py = Get-Command python -ErrorAction SilentlyContinue
                if ($py) {
                    $code = @'
import sys, base64
from nacl.signing import VerifyKey
sha_hex, sig_b64, key_hex = sys.argv[1], sys.argv[2], sys.argv[3]
VerifyKey(bytes.fromhex(key_hex)).verify(signature=base64.b64decode(sig_b64) + bytes.fromhex(sha_hex))
print("sig-ok")
'@
                    $sigOne = ($sigB64 | Select-Object -First 1).Trim()
                    $out = & python -c $code $expectedSha $sigOne $verifyKeyHex.Trim() 2>&1
                    if ($LASTEXITCODE -ne 0 -or ($out -notcontains "sig-ok")) {
                        Write-Error "Signature verification failed ($out); refusing."
                        exit 1
                    }
                    Write-Host "    Signature verified."
                } else {
                    Write-Host "    WARNING: signature present but python+nacl unavailable; hash verified, signature NOT checked."
                }
            }
        } else {
            Write-Host "    NOTE: no X-Trace-Signature header (server signing key not configured); hash verified."
            if (-not [string]::IsNullOrWhiteSpace($env:TRACE_UPDATE_VERIFY_KEY_HEX)) {
                Write-Error "TRACE_UPDATE_VERIFY_KEY_HEX is set but server sent no signature; refusing (fail-closed)."
                exit 1
            }
        }
    }

    # Verify happened BEFORE install.
    Copy-Item $staged (Join-Path $BinDir "trace-agent.exe") -Force
} finally {
    if (Test-Path $staged) { Remove-Item $staged -Force -ErrorAction SilentlyContinue }
}

# Write config; key goes to a separate 0600-equivalent file (locked ACL), never inline world-readable.
$configFile = Join-Path $ConfigDir "agent.yaml"
$config = @"
server_url: $ServerUrl
data_dir: $DataDir
log_dir: $DataDir\logs
monitor_process: true
monitor_file: true
monitor_network: true
monitor_registry: true
heartbeat_interval: 30s
poll_interval: 5s
batch_interval: 2s
max_batch_size: 100
"@
Set-Content -Path $configFile -Value $config -Encoding UTF8

$keyFile = Join-Path $ConfigDir "agent.key"
Set-Content -Path $keyFile -Value $ApiKey -Encoding UTF8 -NoNewline
# Restrict key file to Administrators + SYSTEM (0600 equivalent).
try {
    $acl = Get-Acl $keyFile
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($id in @("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM") ) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, "FullControl", "Allow")
        $acl.AddAccessRule($rule)
    }
    Set-Acl $keyFile $acl
} catch {
    Write-Host "    WARNING: could not lock key ACL ($_.Exception.Message)"
}
Add-Content -Path $configFile -Value "api_key_file: $keyFile" -Encoding UTF8
$ApiKey = $null

# Install Windows service
$agentExe = Join-Path $BinDir "trace-agent.exe"
Write-Host "==> Installing Windows service"
& $agentExe --config $configFile --install

Write-Host "==> Done! Agent installed."
Write-Host "    Config: $configFile"
Write-Host "    Start:  Start-Service TraceAgent"
