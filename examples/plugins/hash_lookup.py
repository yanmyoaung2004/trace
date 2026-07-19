#!/usr/bin/env python3
"""
Trace Sidecar Plugin — Hash Lookup Example

This is a reference implementation of the Trace sidecar plugin protocol.
Plugins communicate over stdin/stdout using JSON-RPC-style messages.

Protocol:
  1. Trace sends: {"id": "req-1", "method": "info", "params": null}
     Plugin responds: {"id": "req-1", "result": {"name": "...", "capabilities": [...]}}

  2. Trace sends: {"id": "req-2", "method": "execute", "params": {"action": "...", "params": {...}}}
     Plugin responds: {"id": "req-2", "result": {"status": "ok", ...}}

To test: python3 hash_lookup.py
  Then type JSON lines on stdin, read responses from stdout.

To use with Trace: LoadSidecar("./hash_lookup.py", [])
"""

import json
import sys
import hashlib

KNOWN_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "reputation": "malicious",
        "name": "Mimikatz",
        "confidence": 0.95,
    },
    "e99a18c428cb38d5f260853678922e03": {
        "reputation": "malicious",
        "name": "EICAR test file",
        "confidence": 1.0,
    },
}

def handle_info():
    return {
        "name": "hash-lookup",
        "description": "Hash reputation lookup",
        "capabilities": [
            {"action": "hash_lookup", "inputs": ["hash"], "outputs": ["reputation", "name", "confidence"]}
        ],
    }

def handle_execute(params):
    action = params.get("action", "")
    action_params = params.get("params", {})

    if action == "hash_lookup":
        hash_val = action_params.get("hash", "").strip().lower()
        if not hash_val:
            return {"status": "error", "error": "hash is required"}

        result = KNOWN_HASHES.get(hash_val)
        if result:
            return {"status": "ok", "reputation": result["reputation"], "name": result["name"], "confidence": result["confidence"]}
        else:
            return {"status": "ok", "reputation": "unknown", "confidence": 0.0}

    return {"status": "error", "error": f"unknown action: {action}"}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            response = {"id": "error", "error": f"invalid JSON: {e}"}
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue

        req_id = request.get("id", "unknown")
        method = request.get("method", "")
        params = request.get("params")

        if method == "info":
            result = handle_info()
            response = {"id": req_id, "result": result}
        elif method == "execute":
            result = handle_execute(params or {})
            if "error" in result:
                response = {"id": req_id, "error": result["error"]}
            else:
                response = {"id": req_id, "result": result}
        else:
            response = {"id": req_id, "error": f"unknown method: {method}"}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
