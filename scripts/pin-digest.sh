#!/bin/sh
# pin-digest.sh — pin the DaemonSet image to tag+digest (W4).
#
# The DaemonSet ships with a failing-closed placeholder digest
# (@sha256:0000...). Never invent or hand-type a digest: take the TAG from
# the pushed release and the DIGEST from `crane digest`, then run this script
# to rewrite the image line keeping tag+digest together.
#
# Usage:
#   TAG=v0.1.1
#   DIGEST=$(crane digest ghcr.io/yanmyoaung2004/trace-agent:${TAG})
#   scripts/pin-digest.sh "${TAG}" "${DIGEST}" [MANIFEST]
#
# Verifies: DIGEST is `sha256:` + 64 lowercase hex; rewrites the
# trace-agent `image:` line; fails if any `0000` placeholder remains;
# prints the verify command. Exits non-zero on any failure.
set -eu

TAG="${1:-}"
DIGEST="${2:-}"
FILE="${3:-deploy/daemonset.yaml}"
IMAGE="ghcr.io/yanmyoaung2004/trace-agent"

if [ -z "$TAG" ] || [ -z "$DIGEST" ]; then
  echo "usage: $0 <TAG> <DIGEST> [MANIFEST]" >&2
  echo "example: $0 v0.1.1 \"\$(crane digest ${IMAGE}:v0.1.1)\"" >&2
  exit 2
fi

case "$TAG" in
  *[!A-Za-z0-9._-]* | "" | -* | .* )
    echo "error: bad TAG '$TAG' (want [A-Za-z0-9._-], no leading ./-)" >&2
    exit 2
    ;;
esac

if ! printf '%s' "$DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
  echo "error: bad DIGEST '$DIGEST' (want sha256: + 64 lowercase hex)" >&2
  exit 2
fi

if [ ! -f "$FILE" ]; then
  echo "error: manifest not found: $FILE" >&2
  exit 2
fi

if ! grep -Eq "image:[[:space:]]*${IMAGE}:" "$FILE"; then
  echo "error: no ${IMAGE} image line in $FILE" >&2
  exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM
sed -E "s|image:[[:space:]]*${IMAGE}:[^[:space:]@]+@sha256:[^[:space:]]+|image: ${IMAGE}:${TAG}@${DIGEST}|" "$FILE" > "$tmp"
cat "$tmp" > "$FILE"
rm -f "$tmp"
trap - EXIT INT TERM

if grep -E '^[[:space:]]*#?[[:space:]]*image:' "$FILE" | grep -q '0000'; then
  echo "error: zero-placeholder digest still present on an image line in $FILE" >&2
  exit 1
fi

echo "pinned: image: ${IMAGE}:${TAG}@${DIGEST}"
echo "verify:"
echo "  grep 'image:' $FILE"
echo "  crane digest ${IMAGE}:${TAG}   # must print ${DIGEST}"
