#!/usr/bin/env bash
set -euo pipefail

# Trace Agent Installer — Linux / macOS
# Usage: bash install.sh [--server <url>] [--api-key <key> | --api-key-file <path>]
#        TRACE_API_KEY / TRACE_API_KEY_FILE also accepted (file wins for hygiene).
#
# Download contract (agreed with server owner):
#   GET <server>/api/v1/edr/update/download?os=<os>&arch=<arch>
#   Authorization: Bearer <api-key> (required)
# Server answers with the binary plus:
#   X-Trace-SHA256    hex sha256 of the bytes (always)
#   X-Trace-Signature base64 ed25519 over the raw digest (when the server
#                   signing key is configured; absent otherwise)
# The installer verifies hash (+ signature via TRACE_UPDATE_VERIFY_KEY_HEX
# when set) BEFORE chmod, and writes the key file 0600.

SERVER_URL="${TRACE_SERVER_URL:-https://127.0.0.1:8080}"
API_KEY="${TRACE_API_KEY:-}"
API_KEY_FILE="${TRACE_API_KEY_FILE:-}"
VERIFY_KEY_HEX="${TRACE_UPDATE_VERIFY_KEY_HEX:-}"
BIN_DIR="/usr/local/bin"
DATA_DIR="/var/lib/trace-agent"
CONFIG_DIR="/etc/trace-agent"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --api-key-file) API_KEY_FILE="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -n "$API_KEY_FILE" ]]; then
  if [[ ! -f "$API_KEY_FILE" ]]; then echo "API key file not found: $API_KEY_FILE"; exit 1; fi
  API_KEY="$(tr -d ' \t\r\n' < "$API_KEY_FILE")"
fi
if [[ -z "$API_KEY" ]]; then
  echo "ERROR: an API key is required (--api-key, --api-key-file, TRACE_API_KEY, or TRACE_API_KEY_FILE)."
  echo "The download endpoint is authenticated; anonymous download is refused."
  exit 1
fi

echo "==> Trace Agent Installer"
echo "    Server: $SERVER_URL"
echo "    Binary: $BIN_DIR/trace-agent"
echo "    Config: $CONFIG_DIR/agent.yaml"
echo "    Data:   $DATA_DIR"

# Detect OS/arch (server ?os=&arch= selection values)
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
  linux) OS="linux" ;;
  darwin) OS="darwin" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

sudo mkdir -p "$BIN_DIR" "$DATA_DIR" "$CONFIG_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STAGED="$(mktemp -d)/trace-agent"
trap 'rm -f "$STAGED" "$STAGED.headers"' EXIT

if [ -f "$SCRIPT_DIR/trace-agent" ]; then
  echo "==> Installing from local binary (no network verify; ensure your checkout is trusted)"
  cp "$SCRIPT_DIR/trace-agent" "$STAGED"
else
  DOWNLOAD_URL="${SERVER_URL}/api/v1/edr/update/download?os=${OS}&arch=${ARCH}"
  echo "==> Downloading (authenticated) from $DOWNLOAD_URL"
  sudo curl -fsSL --proto '=https' --tlsv1.2 \
    -H "Authorization: Bearer ${API_KEY}" \
    -D "$STAGED.headers" -o "$STAGED" "$DOWNLOAD_URL"
  EXPECTED_SHA="$(grep -i '^X-Trace-SHA256:' "$STAGED.headers" | tr -d '\r' | awk '{print $2}' | tr -d ' \t' | tr '[:upper:]' '[:lower:]' || true)"
  SIG_B64="$(grep -i '^X-Trace-Signature:' "$STAGED.headers" | tr -d '\r' | awk '{print $2}' | tr -d ' \t' || true)"
  if [[ -z "$EXPECTED_SHA" ]]; then
    echo "ERROR: server did not return X-Trace-SHA256; refusing unverified binary."
    exit 1
  fi
  GOT_SHA="$(sha256sum "$STAGED" | awk '{print $1}')"
  if [[ "$GOT_SHA" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: checksum mismatch (got $GOT_SHA, expected $EXPECTED_SHA); refusing."
    exit 1
  fi
  echo "    Checksum verified: $GOT_SHA"
  if [[ -n "$SIG_B64" ]]; then
    if [[ -n "$VERIFY_KEY_HEX" ]]; then
      if command -v python3 >/dev/null 2>&1; then
        SIG_OK="$(python3 - "$STAGED" "$EXPECTED_SHA" "$SIG_B64" "$VERIFY_KEY_HEX" <<'PYEOF' || echo "verify-error"
import sys, hashlib, base64
try:
    from nacl.signing import VerifyKey
    have_nacl = True
except ImportError:
    have_nacl = False
path, sha_hex, sig_b64, key_hex = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
raw = bytes.fromhex(sha_hex)
sig = base64.b64decode(sig_b64)
if not have_nacl:
    print("no-pynacl")
    sys.exit(0)
VerifyKey(bytes.fromhex(key_hex)).verify(signature=sig + raw)
print("sig-ok")
PYEOF
)"
        case "$SIG_OK" in
          sig-ok) echo "    Signature verified." ;;
          no-pynacl) echo "    WARNING: signature present but python3-nacl unavailable; hash verified, signature NOT checked. Install python3-nacl for full verification." ;;
          *) echo "ERROR: signature verification failed ($SIG_OK); refusing."; exit 1 ;;
        esac
      else
        echo "    WARNING: signature present but python3 unavailable; hash verified, signature NOT checked."
      fi
    else
      echo "    WARNING: server sent a signature but TRACE_UPDATE_VERIFY_KEY_HEX is unset; hash verified, signature NOT checked."
    fi
  else
    echo "    NOTE: no X-Trace-Signature header (server signing key not configured); hash verified."
    if [[ -n "$VERIFY_KEY_HEX" ]]; then
      echo "ERROR: TRACE_UPDATE_VERIFY_KEY_HEX is set but server sent no signature; refusing (fail-closed)."
      exit 1
    fi
  fi
fi

# Verify BEFORE chmod + install.
sudo install -m 0755 "$STAGED" "$BIN_DIR/trace-agent"

# Write config (0600 when it carries a key; key never world-readable).
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
sudo chmod 0600 "$CONFIG_FILE"

if [[ -n "${API_KEY_FILE:-}" && -f "$API_KEY_FILE" ]]; then
  echo "api_key_file: ${API_KEY_FILE}" | sudo tee -a "$CONFIG_FILE" > /dev/null
else
  KEY_FILE="$CONFIG_DIR/agent.key"
  printf '%s' "$API_KEY" | sudo tee "$KEY_FILE" > /dev/null
  sudo chmod 0600 "$KEY_FILE"
  echo "api_key_file: ${KEY_FILE}" | sudo tee -a "$CONFIG_FILE" > /dev/null
fi
sudo chmod 0600 "$CONFIG_FILE"
unset API_KEY

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
echo "    Config: $CONFIG_FILE (0600)"
echo "    Logs:   /var/log/trace-agent/"
