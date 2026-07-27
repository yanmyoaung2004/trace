#!/usr/bin/env bash
set -euo pipefail

# Trace Agent Installer — Linux / macOS
# Usage: curl -fsSL https://trace.dev/install.sh | bash
#        bash install.sh [--server <url>] [--api-key <key>]

SERVER_URL="${TRACE_SERVER_URL:-https://127.0.0.1:8443}"
API_KEY=""
BIN_DIR="/usr/local/bin"
DATA_DIR="/var/lib/trace-agent"
CONFIG_DIR="/etc/trace-agent"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

echo "==> Trace Agent Installer"
echo "    Server: $SERVER_URL"
echo "    Binary: $BIN_DIR/trace-agent"
echo "    Config: $CONFIG_DIR/agent.yaml"
echo "    Data:   $DATA_DIR"

# Detect OS/arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Make directories
sudo mkdir -p "$BIN_DIR" "$DATA_DIR" "$CONFIG_DIR"

# Copy binary (assumes install.sh is next to trace-agent)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/trace-agent" ]; then
  echo "==> Installing from local binary"
  sudo cp "$SCRIPT_DIR/trace-agent" "$BIN_DIR/trace-agent"
else
  # Download from server
  DOWNLOAD_URL="${SERVER_URL}/api/v1/edr/update/download?os=${OS}&arch=${ARCH}"
  echo "==> Downloading from $DOWNLOAD_URL"
  sudo curl -fsSL -o "$BIN_DIR/trace-agent" "$DOWNLOAD_URL"
fi
sudo chmod 755 "$BIN_DIR/trace-agent"

# Write config
CONFIG_FILE="$CONFIG_DIR/agent.yaml"
sudo tee "$CONFIG_FILE" > /dev/null <<EOF
server_url: ${SERVER_URL}
data_dir: ${DATA_DIR}
log_dir: /var/log/trace-agent
monitor_process: true
monitor_file: true
monitor_network: true
monitor_registry: false
heartbeat_interval: 30s
poll_interval: 5s
batch_interval: 2s
max_batch_size: 100
EOF

if [ -n "$API_KEY" ]; then
  echo "api_key: ${API_KEY}" | sudo tee -a "$CONFIG_FILE" > /dev/null
fi

# Install system service
echo "==> Installing system service"
sudo "$BIN_DIR/trace-agent" --config "$CONFIG_FILE" --install

# Start service
echo "==> Starting service"
if command -v systemctl &>/dev/null; then
  sudo systemctl start trace-agent
  sudo systemctl enable trace-agent
  sudo systemctl status trace-agent --no-pager
else
  echo "==> Service installed. Start manually or reboot."
fi

echo "==> Done! Agent installed and running."
echo "    Config: $CONFIG_FILE"
echo "    Logs:   /var/log/trace-agent/"
