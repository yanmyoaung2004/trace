<#
.SYNOPSIS
    Trace Agent Installer — Windows
.DESCRIPTION
    Installs trace-agent as a Windows service.
    Usage: .\install.ps1 -ServerUrl https://trace-server:8443 -ApiKey "key"
#>

param(
    [string]$ServerUrl = "https://127.0.0.1:8443",
    [string]$ApiKey = "",
    [string]$BinDir = "$env:ProgramFiles\Trace\Agent",
    [string]$DataDir = "$env:ProgramData\Trace\Agent",
    [string]$ConfigDir = "$env:ProgramData\Trace\Agent"
)

Write-Host "==> Trace Agent Installer (Windows)"
Write-Host "    Server: $ServerUrl"
Write-Host "    Binary: $BinDir\trace-agent.exe"

# Create directories
New-Item -ItemType Directory -Force -Path $BinDir, $DataDir, $ConfigDir | Out-Null

# Copy binary (assumes install.ps1 is next to trace-agent.exe)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$localBin = Join-Path $scriptDir "trace-agent.exe"
if (Test-Path $localBin) {
    Write-Host "==> Installing from local binary"
    Copy-Item $localBin (Join-Path $BinDir "trace-agent.exe") -Force
} else {
    # Download from server
    $downloadUrl = "${ServerUrl}/api/v1/edr/update/download?os=windows&arch=amd64"
    Write-Host "==> Downloading from $downloadUrl"
    Invoke-WebRequest -Uri $downloadUrl -OutFile (Join-Path $BinDir "trace-agent.exe")
}

# Write config
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

if ($ApiKey) {
    $config += "`api_key: $ApiKey"
}

Set-Content -Path $configFile -Value $config -Encoding UTF8

# Install Windows service
$agentExe = Join-Path $BinDir "trace-agent.exe"
Write-Host "==> Installing Windows service"
& $agentExe --config $configFile --install

Write-Host "==> Done! Agent installed."
Write-Host "    Config: $configFile"
Write-Host "    Start:  Start-Service TraceAgent"
