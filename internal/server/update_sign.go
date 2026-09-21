package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
)

// updateSignatureFor signs the update binding (version+sha: sha is the raw
// 32-byte digest the server computed for the published version in the
// check response) with the ed25519 private key in TRACE_UPDATE_SIGNING_KEY
// (base64 32-byte seed or 64-byte private key), returning base64(sig).
// The signature is dual-published: as "signature" in the check JSON
// (agent trust root) and as X-Trace-Signature on the download response
// (installer verifies before chmod). Empty when no key is configured
// (SHA-only mode; serve logs a plaintext warn in that case) -- SHA-only
// stays warn, never refusal, until keys are provisioned fleet-wide.
//
// Key ceremony: generate ed25519 offline, keep the private key off the
// fleet (server env only), publish the 32-byte hex public key to agents
// as TRACE_UPDATE_VERIFY_KEY_HEX, dual-publish .sha256 + .sig one
// release unsigned-tolerant, then enforce (agents fail-closed when keyed
// but the signature is absent).
func updateSignatureFor(sha []byte) string {
	raw := strings.TrimSpace(os.Getenv("TRACE_UPDATE_SIGNING_KEY"))
	if raw == "" {
		return ""
	}
	keyBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		keyBytes, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return ""
		}
	}
	var priv ed25519.PrivateKey
	switch len(keyBytes) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(keyBytes)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(append([]byte(nil), keyBytes...))
	default:
		return ""
	}
	sig := ed25519.Sign(priv, sha)
	return base64.StdEncoding.EncodeToString(sig)
}
