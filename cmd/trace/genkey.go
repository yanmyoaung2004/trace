package main

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

func newGenKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a self-signed TLS certificate and key",
		Long: `Generate a self-signed TLS certificate and RSA key for development use.
Example:
  trace genkey --host localhost --out ~/.trace/tls`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			host, _ := cmdCobra.Flags().GetString("host")
			outDir, _ := cmdCobra.Flags().GetString("out")
			bits, _ := cmdCobra.Flags().GetInt("bits")

			if host == "" {
				host = "localhost"
			}
			if outDir == "" {
				home, _ := os.UserHomeDir()
				outDir = filepath.Join(home, ".trace", "tls")
			}

			os.MkdirAll(outDir, 0700)

			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
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
				return fmt.Errorf("create cert: %w", err)
			}

			certPath := filepath.Join(outDir, "cert.pem")
			keyPath := filepath.Join(outDir, "key.pem")

			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644); err != nil {
				return fmt.Errorf("write cert file: %w", err)
			}

			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			}), 0600); err != nil {
				return fmt.Errorf("write key file: %w", err)
			}
			// Enforce 0600 even if the file pre-existed (Chmod, not just create mode).
			if err := os.Chmod(keyPath, 0600); err != nil {
				return fmt.Errorf("chmod key file: %w", err)
			}
			fmt.Printf("TLS certificate generated:\n")
			fmt.Printf("Start server with:\n")
			fmt.Printf("  trace server --tls-cert %s --tls-key %s\n", certPath, keyPath)
			return nil
		},
	}

	cmd.Flags().String("host", "localhost", "certificate hostname or IP")
	cmd.Flags().String("out", "", "output directory (default ~/.trace/tls)")
	cmd.Flags().Int("bits", 2048, "RSA key size in bits")
	return cmd
}
