package main

// trace update-keys: offline tooling for the update-signing ceremony.
//
// Byte layout (mirrors the fleet verify path exactly — do not change one
// without the other):
//   - "<artifact>.sha256" holds "<hex-digest>  <basename>\n" (sha256sum
//     format; consumers take the first whitespace field, see
//     fetchExpectedHash in update.go).
//   - "<artifact>.sig" holds base64(stdlib StdEncoding) of the ed25519
//     signature over the RAW 32-byte digest (not over the hex string).
//     That matches internal/server/update_sign.go updateSignatureFor
//     (ed25519.Sign(priv, sha)) and the verifiers in
//     internal/edr_agent/updater/updater.go verifySignatureHex and
//     cmd/trace/update.go verifyArtifactSignature
//     (ed25519.Verify(key, digest, sig)).
//   - Signing key input is base64 (Std, then URLEncoding fallback) of the
//     32-byte seed or 64-byte private key — same accepted forms as
//     updateSignatureFor. Verify key is 32-byte hex public key, same as
//     TRACE_UPDATE_VERIFY_KEY_HEX.
//
// This tool mints/checks artifacts only. It is NOT wired into the updater
// trust root: agents stay fail-closed (refuse everything when unkeyed via
// verifySignatureHex) regardless of this tool.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// loadUpdateSigningKey parses TRACE_UPDATE_SIGNING_KEY-form input: base64
// (Std, then URLEncoding) of a 32-byte seed or 64-byte private key.
func loadUpdateSigningKey(raw string) (ed25519.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no signing key: pass --key or set TRACE_UPDATE_SIGNING_KEY (base64 32-byte seed or 64-byte private key)")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		keyBytes, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("malformed signing key: not base64")
		}
	}
	switch len(keyBytes) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(keyBytes), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), keyBytes...)), nil
	default:
		return nil, fmt.Errorf("malformed signing key: want 32-byte seed or 64-byte private key, got %d bytes", len(keyBytes))
	}
}

// loadUpdateVerifyKey parses TRACE_UPDATE_VERIFY_KEY_HEX-form input:
// 64 hex chars (32-byte ed25519 public key).
func loadUpdateVerifyKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("malformed verify key: want 64 hex chars (32-byte ed25519 public key)")
	}
	return ed25519.PublicKey(b), nil
}

// releaseArtifacts lists publishable files in dir: regular files, sorted,
// excluding existing .sha256/.sig sidecars.
func releaseArtifacts(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read release dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".sha256") || strings.HasSuffix(name, ".sig") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func sha256OfFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func newUpdateKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-keys",
		Short: "Offline update-signing ceremony tooling (gen/publish/verify)",
		Long: `Offline tooling for the update-signing ceremony.

Byte layout matches the fleet verify path: .sha256 sidecars hold the hex
digest, .sig sidecars hold base64 ed25519 over the RAW 32-byte digest
(see internal/server/update_sign.go and internal/edr_agent/updater).

Key ceremony stays operator-side: generate offline, keep the private seed
off the fleet (server env TRACE_UPDATE_SIGNING_KEY only), publish the hex
public key to agents as TRACE_UPDATE_VERIFY_KEY_HEX.`,
	}

	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate an offline ed25519 update-signing keypair",
		Long: `Generate an ed25519 keypair for update signing.

Prints the public key hex (provision to agents as
TRACE_UPDATE_VERIFY_KEY_HEX) plus seed-handling instructions.

The private seed is NEVER printed when --out is given (it goes only to
the 0600 file). Without --out the base64 seed is printed EXACTLY ONCE —
save it now; it is never shown again.`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			out, _ := cmdCobra.Flags().GetString("out")
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
			seedB64 := base64.StdEncoding.EncodeToString(priv.Seed())
			pubHex := hex.EncodeToString(pub)
			if out != "" {
				if err := os.WriteFile(out, []byte(seedB64+"\n"), 0600); err != nil {
					return fmt.Errorf("write seed file: %w", err)
				}
				// Enforce 0600 even if the file pre-existed.
				if err := os.Chmod(out, 0600); err != nil {
					return fmt.Errorf("chmod seed file: %w", err)
				}
				fmt.Printf("Public key (TRACE_UPDATE_VERIFY_KEY_HEX):\n%s\n", pubHex)
				fmt.Printf("Private seed written to %s (mode 0600, not shown here).\n", out)
				fmt.Printf("Set on the server only: TRACE_UPDATE_SIGNING_KEY=$(cat %s)\n", out)
				fmt.Printf("Keep the seed offline; it never leaves the signing machine.\n")
				return nil
			}
			fmt.Printf("Public key (TRACE_UPDATE_VERIFY_KEY_HEX):\n%s\n\n", pubHex)
			fmt.Printf("Private seed (TRACE_UPDATE_SIGNING_KEY) — shown ONCE, save it now:\n%s\n\n", seedB64)
			fmt.Printf("Handle as a secret: store offline, never commit, never log again.\n")
			return nil
		},
	}
	genCmd.Flags().String("out", "", "write the private seed (base64) to this file with mode 0600 instead of printing it")

	publishCmd := &cobra.Command{
		Use:   "publish",
		Short: "Write .sha256+.sig sidecars for every artifact in a release dir",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			dir, _ := cmdCobra.Flags().GetString("dir")
			keyFlag, _ := cmdCobra.Flags().GetString("key")
			if strings.TrimSpace(dir) == "" {
				return fmt.Errorf("--dir is required")
			}
			raw := keyFlag
			if strings.TrimSpace(raw) == "" {
				raw = os.Getenv("TRACE_UPDATE_SIGNING_KEY")
			}
			priv, err := loadUpdateSigningKey(raw)
			if err != nil {
				return err
			}
			names, err := releaseArtifacts(dir)
			if err != nil {
				return err
			}
			if len(names) == 0 {
				return fmt.Errorf("refusing: no artifacts in %s", dir)
			}
			for _, name := range names {
				digest, err := sha256OfFile(filepath.Join(dir, name))
				if err != nil {
					return fmt.Errorf("hash %s: %w", name, err)
				}
				shaHex := hex.EncodeToString(digest)
				if err := os.WriteFile(filepath.Join(dir, name+".sha256"), []byte(shaHex+"  "+name+"\n"), 0644); err != nil {
					return fmt.Errorf("write %s.sha256: %w", name, err)
				}
				// Sign the raw digest bytes — same input updateSignatureFor signs.
				sig := ed25519.Sign(priv, digest)
				if err := os.WriteFile(filepath.Join(dir, name+".sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil {
					return fmt.Errorf("write %s.sig: %w", name, err)
				}
				fmt.Printf("published %s  sha256:%s\n", name, shaHex)
			}
			return nil
		},
	}
	publishCmd.Flags().String("dir", "", "release directory holding the artifacts (required)")
	publishCmd.Flags().String("key", "", "base64 signing seed/private key (default: TRACE_UPDATE_SIGNING_KEY env)")

	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Locally check a published release dir (fail-closed on missing/mismatch)",
		Long: `Locally check a published release dir.

Every artifact must have a .sha256 sidecar whose hex digest matches the
file bytes (missing/mismatch refuses). When a verify key is configured
(--verify-key or TRACE_UPDATE_VERIFY_KEY_HEX) every artifact must also
have a .sig sidecar that verifies as base64 ed25519 over the raw digest.
Without a key the .sig presence is checked but signatures warn-only
(sha256 still enforced) — provision a key to fully check a release.`,
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			dir, _ := cmdCobra.Flags().GetString("dir")
			keyFlag, _ := cmdCobra.Flags().GetString("verify-key")
			if strings.TrimSpace(dir) == "" {
				return fmt.Errorf("--dir is required")
			}
			raw := keyFlag
			if strings.TrimSpace(raw) == "" {
				raw = os.Getenv("TRACE_UPDATE_VERIFY_KEY_HEX")
			}
			key, err := loadUpdateVerifyKey(raw)
			if err != nil {
				return err
			}
			if len(key) == 0 {
				fmt.Fprintln(os.Stderr, "Warning: no verify key configured; sha256-only verification (pass --verify-key or set TRACE_UPDATE_VERIFY_KEY_HEX for signed checks).")
			}
			names, err := releaseArtifacts(dir)
			if err != nil {
				return err
			}
			if len(names) == 0 {
				return fmt.Errorf("refusing: no artifacts in %s", dir)
			}
			for _, name := range names {
				sidecar, err := os.ReadFile(filepath.Join(dir, name+".sha256"))
				if err != nil {
					return fmt.Errorf("refusing %s: no .sha256 sidecar — publish checksums before verifying", name)
				}
				field := strings.Fields(string(sidecar))
				if len(field) == 0 {
					return fmt.Errorf("refusing %s: empty .sha256 sidecar", name)
				}
				shaHex := strings.ToLower(strings.TrimSpace(field[0]))
				want, err := hex.DecodeString(shaHex)
				if err != nil || len(want) != sha256.Size {
					return fmt.Errorf("refusing %s: malformed .sha256 sidecar", name)
				}
				got, err := sha256OfFile(filepath.Join(dir, name))
				if subtle.ConstantTimeCompare(got, want) != 1 {
					return fmt.Errorf("refusing %s: sha256 mismatch", name)
				}
				sigRaw, err := os.ReadFile(filepath.Join(dir, name+".sig"))
				if err != nil {
					if len(key) == ed25519.PublicKeySize {
						return fmt.Errorf("refusing %s: verify key configured but no .sig published", name)
					}
					fmt.Fprintf(os.Stderr, "Warning: %s has no .sig sidecar; sha256-only verification.\n", name)
					continue
				}
				sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
				if err != nil || len(sig) != ed25519.SignatureSize {
					return fmt.Errorf("refusing %s: malformed .sig sidecar", name)
				}
				if len(key) != ed25519.PublicKeySize {
					fmt.Fprintf(os.Stderr, "Warning: %s has .sig but no verify key configured; sha256-only verification.\n", name)
					continue
				}
				if !ed25519.Verify(key, got, sig) {
					return fmt.Errorf("refusing %s: signature verification failed", name)
				}
				fmt.Printf("verified %s  sha256+sig ok\n", name)
			}
			return nil
		},
	}
	verifyCmd.Flags().String("dir", "", "published release directory to check (required)")
	verifyCmd.Flags().String("verify-key", "", "hex ed25519 public key (default: TRACE_UPDATE_VERIFY_KEY_HEX env)")

	cmd.AddCommand(genCmd, publishCmd, verifyCmd)
	return cmd
}
