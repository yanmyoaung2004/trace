package main

// Shared --tls-auto / --tls-require helper for the central server path
// (W1: TLS-auto + plaintext-refuse flag).
//
// The `serve` daemon path starts no HTTP listener of its own — its only
// `--tls-*` use is the --export HTML report server (plaintext, see
// serve.go) and the --server-addr edge-sync client. ServeHTTP is only
// invoked via server.RunServer from the `server` command, so the TLS
// flags are wired where ServeHTTP is actually invoked: server_cmd.go.
// serve.go keeps its existing --tls-cert/--tls-key/--tls-auto flags for
// forward compatibility but documents that TLS terminates at `server`.
//
// --tls-auto uses the same generator logic as genkey.go: RSA-2048
// self-signed cert into ~/.trace/tls/ (dir 0700, cert 0644, key 0600
// enforced via Chmod even when the key file pre-existed).
// --tls-require refuses to serve plaintext (default: warn, matching
// internal/server/admin.go ServeHTTP plaintext behaviour).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// defaultTLSDir returns ~/.trace/tls (same default as genkey --out).
func defaultTLSDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trace", "tls")
}

// ensureSelfSignedTLS generates (or reuses, when both files already exist)
// a genkey-equivalent self-signed pair in dir. Permissions mirror genkey.go:
// dir 0700, cert 0644, key 0600 (+Chmod so a pre-existing key is tightened).
func ensureSelfSignedTLS(dir, host string) (certPath, keyPath string, err error) {
	if dir == "" {
		dir = defaultTLSDir()
	}
	if host == "" {
		host = "localhost"
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("create tls dir: %w", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// Reuse existing pair but enforce the documented permissions.
			if err := os.Chmod(keyPath, 0600); err != nil {
				return "", "", fmt.Errorf("chmod key file: %w", err)
			}
			if err := os.Chmod(certPath, 0644); err != nil {
				return "", "", fmt.Errorf("chmod cert file: %w", err)
			}
			return certPath, keyPath, nil
		}
	}

	// Same generator logic as genkey.go (RSA-2048, 1-year self-signed).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Trace Dev"},
			CommonName:   host,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}
	template.DNSNames = append(template.DNSNames, "localhost")

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %w", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
		return "", "", fmt.Errorf("write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0600); err != nil {
		return "", "", fmt.Errorf("write key file: %w", err)
	}
	// Enforce 0600 even if the file pre-existed (Chmod, not just create mode).
	if err := os.Chmod(keyPath, 0600); err != nil {
		return "", "", fmt.Errorf("chmod key file: %w", err)
	}
	return certPath, keyPath, nil
}

// resolveServerTLS applies --tls-cert/--tls-key/--tls-auto/--tls-require
// from cmd onto the server TLS config. cert/key now carry the resolved
// file paths (after --tls-auto generation, if requested).
// Returns an error when --tls-require is set but no cert/key pair results.
func resolveServerTLS(cmd *cobra.Command, cert, key *string) error {
	tlsAuto, _ := cmd.Flags().GetBool("tls-auto")
	if tlsAuto && *cert == "" && *key == "" {
		certPath, keyPath, err := ensureSelfSignedTLS(defaultTLSDir(), "localhost")
		if err != nil {
			return err
		}
		*cert = certPath
		*key = keyPath
	}
	requirePlaintext, _ := cmd.Flags().GetBool("tls-require")
	if requirePlaintext && (*cert == "" || *key == "") {
		return fmt.Errorf("refusing plaintext: --tls-require set but no TLS cert/key (use --tls-cert/--tls-key or --tls-auto)")
	}
	return nil
}
