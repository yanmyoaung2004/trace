package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
)

// updateSignatureFor signs sha (raw 32 bytes) with the ed25519 private key in
// TRACE_UPDATE_SIGNING_KEY (base64 32-byte seed or 64-byte private key),
// returning base64(sig). Empty when no key is configured (SHA-only mode;
// serve logs a plaintext warn in that case).
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
