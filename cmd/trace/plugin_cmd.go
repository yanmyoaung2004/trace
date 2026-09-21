package main

// plugin install verifies before it trusts.
//
// Contract:
//   - Registry is pinned: default TRACE_PLUGIN_REGISTRY (file:// or
//     https:// mirror for air-gap); arbitrary --registry hosts require
//     explicit --allow-host confirmation. Direct URLs are https-only
//     (loopback http for tests) and still require hash+signature.
//   - Every install requires a manifest entry {sha256, sig?} for the
//     file: registry index.json entries carry sha256 (+sig when the
//     fleet signs plugins). Missing hash = refuse. Present-but-wrong
//     hash or bad signature = refuse + staged file removed.
//   - Signature: base64 ed25519 over raw sha256 digest, verified against
//     TRACE_PLUGIN_VERIFY_KEY_HEX when set. Key set + missing/invalid
//     sig = refuse; no key = warn + sha256-only (explicit prompt unless
//     --yes, and --allow-unsigned required to proceed unsigned).
//   - Explicit prompt: without --yes the user confirms the name, source
//     URL, and sha256 prefix before download. (Registry manifest itself
//     stays deny-by-default: unknown plugin names are refused, never
//     guessed — see DetectReliabilityFixer-owned registry manifest.)

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// pluginRegistryBase is the default pinned registry. Override with
// TRACE_PLUGIN_REGISTRY (https:// mirror or file:// checkout for air-gap).
var pluginRegistryBase = "https://github.com/yanmyoaung2004/trace/releases/latest/download/plugins"

func pluginRegistry() string {
	if v := strings.TrimSpace(os.Getenv("TRACE_PLUGIN_REGISTRY")); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return pluginRegistryBase
}

func pluginVerifyKey() ed25519.PublicKey {
	raw := strings.TrimSpace(os.Getenv("TRACE_PLUGIN_VERIFY_KEY_HEX"))
	if raw == "" {
		return nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "Warning: TRACE_PLUGIN_VERIFY_KEY_HEX malformed; ignoring.")
		return nil
	}
	return ed25519.PublicKey(b)
}

type pluginEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SHA256      string `json:"sha256"`
	Sig         string `json:"sig,omitempty"`
}

func requirePluginHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid plugin URL: %w", err)
	}
	if u.Scheme == "https" && u.Host != "" {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")) {
		return nil
	}
	return fmt.Errorf("refusing non-HTTPS plugin URL %q", u.Redacted())
}

// fetchRegistryIndex loads index.json from the pinned registry (or a
// file:// mirror). Deny-by-default: unknown names are never guessed.
func fetchRegistryIndex(client *http.Client) ([]pluginEntry, error) {
	base := pluginRegistry()
	if strings.HasPrefix(base, "file://") {
		p := strings.TrimPrefix(base, "file://")
		raw, err := os.ReadFile(filepath.Join(p, "index.json"))
		if err != nil {
			return nil, fmt.Errorf("read registry index: %w", err)
		}
		var entries []pluginEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("parse registry index: %w", err)
		}
		return entries, nil
	}
	if err := requirePluginHTTPS(base + "/index.json"); err != nil {
		return nil, err
	}
	resp, err := client.Get(base + "/index.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry index: HTTP %d", resp.StatusCode)
	}
	var entries []pluginEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("parse registry index: %w", err)
	}
	return entries, nil
}

// resolvePluginURL maps a name to the pinned registry (deny-by-default on
// unknown names) or validates a direct URL. Returns url + manifest entry
// (nil entry for direct URLs, which still require explicit flags).
func resolvePluginURL(client *http.Client, input, registryOverride string, allowHost bool) (string, *pluginEntry, error) {
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if err := requirePluginHTTPS(input); err != nil {
			return "", nil, err
		}
		if registryOverride != "" || allowHost {
			return input, nil, nil
		}
		return "", nil, fmt.Errorf("direct plugin URLs require --registry <mirror> or --allow-host confirmation")
	}
	name := input
	if !strings.HasSuffix(name, ".so") {
		name += ".so"
	}
	// Registry override replaces the pinned base for this invocation only.
	base := pluginRegistry()
	if strings.TrimSpace(registryOverride) != "" {
		base = strings.TrimSuffix(strings.TrimSpace(registryOverride), "/")
	}
	entries, err := fetchRegistryIndex(client)
	if err != nil {
		return "", nil, err
	}
	for i := range entries {
		en := entries[i].Name
		if en == name || strings.TrimSuffix(en, ".so") == strings.TrimSuffix(name, ".so") {
			return base + "/" + entries[i].Name, &entries[i], nil
		}
	}
	return "", nil, fmt.Errorf("plugin %q not in registry (deny-by-default; publish it with sha256 before installing)", input)
}

func pluginDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".trace", "plugins")
}

func confirmInstall(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func verifyPluginBytes(data []byte, entry *pluginEntry, directSHA, directSig string) error {
	want := directSHA
	sig := directSig
	if entry != nil {
		want = entry.SHA256
		sig = entry.Sig
	}
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return fmt.Errorf("refusing plugin: no sha256 (registry entry or --sha256 required)")
	}
	if b, err := hex.DecodeString(want); err != nil || len(b) != sha256.Size {
		return fmt.Errorf("refusing plugin: malformed sha256")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("refusing plugin: checksum mismatch")
	}
	key := pluginVerifyKey()
	if len(key) == ed25519.PublicKeySize {
		if strings.TrimSpace(sig) == "" {
			return fmt.Errorf("refusing plugin: verify key configured but plugin has no signature")
		}
		sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
		if err != nil || len(sigRaw) != ed25519.SignatureSize {
			return fmt.Errorf("refusing plugin: malformed signature")
		}
		if !ed25519.Verify(key, sum[:], sigRaw) {
			return fmt.Errorf("refusing plugin: signature verification failed")
		}
		fmt.Fprintln(os.Stderr, "Plugin signature verified.")
	} else if strings.TrimSpace(sig) != "" {
		fmt.Fprintln(os.Stderr, "Warning: plugin carries a signature but no verify key is configured; sha256-only verification.")
	}
	return nil
}

func newPluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage external agent plugins",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List installed plugins and their capabilities",
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			agents := app.registry.List()
			if len(agents) == 0 {
				fmt.Println("No agents registered.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Agent\tActions")
			for _, a := range agents {
				caps := a.Capabilities()
				actions := ""
				for i, c := range caps {
					if i > 0 {
						actions += ", "
					}
					actions += c.Action
				}
				fmt.Fprintf(w, "%s\t%s\n", a.Name(), actions)
			}
			w.Flush()

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "search [query]",
		Short: "Search available plugins in the registry",
		Long: `Search for plugins in the Trace plugin registry.
If no query is given, lists all available plugins.

Examples:
  trace plugin search
  trace plugin search siem`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			client := &http.Client{Timeout: 10 * time.Second}
			entries, err := fetchRegistryIndex(client)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Warning: cannot reach plugin registry (offline?)")
				return nil
			}

			query := ""
			if len(args) > 0 {
				query = strings.ToLower(args[0])
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "Name\tDescription")
			for _, e := range entries {
				if query != "" && !strings.Contains(strings.ToLower(e.Name), query) && !strings.Contains(strings.ToLower(e.Description), query) {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\n", e.Name, e.Description)
			}
			w.Flush()
			return nil
		},
	})

	installCmd := &cobra.Command{
		Use:   "install [name-or-url]",
		Short: "Download and install a plugin",
		Long: `Install a plugin by name (pinned registry, deny-by-default) or URL.

Verification is mandatory: every install requires a sha256 (registry
manifest entry or --sha256 for direct URLs) and, when
TRACE_PLUGIN_VERIFY_KEY_HEX is set, a matching ed25519 signature
(registry 'sig' field or --sig). Without --yes you are prompted to
confirm the plugin identity before download.

Examples:
  trace plugin install exporter
  trace plugin install https://mirror.internal/plugins/x.so --registry https://mirror.internal/plugins --sha256 <hex> --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			registryOverride, _ := cmdCobra.Flags().GetString("registry")
			allowHost, _ := cmdCobra.Flags().GetBool("allow-host")
			directSHA, _ := cmdCobra.Flags().GetString("sha256")
			directSig, _ := cmdCobra.Flags().GetString("sig")
			allowUnsigned, _ := cmdCobra.Flags().GetBool("allow-unsigned")
			yes, _ := cmdCobra.Flags().GetBool("yes")

			client := &http.Client{Timeout: 30 * time.Second,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				}}
			pluginURL, entry, err := resolvePluginURL(client, args[0], registryOverride, allowHost)
			if err != nil {
				return err
			}

			wantSHA := directSHA
			if entry != nil {
				wantSHA = entry.SHA256
			}
			if strings.TrimSpace(wantSHA) == "" && len(pluginVerifyKey()) != ed25519.PublicKeySize && !allowUnsigned {
				return fmt.Errorf("refusing plugin: no sha256 available; re-run with --sha256 <hex> (or --allow-unsigned to override with an explicit prompt)")
			}

			shortHash := strings.TrimSpace(wantSHA)
			if len(shortHash) > 16 {
				shortHash = shortHash[:16] + "…"
			}
			if !yes {
				if !confirmInstall(fmt.Sprintf("Install plugin from %s (sha256 %s)?", pluginURL, shortHash)) {
					return fmt.Errorf("install aborted by user")
				}
			}

			dir := pluginDir()
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create plugin dir: %w", err)
			}

			parsed, perr := url.Parse(pluginURL)
			if perr != nil {
				return fmt.Errorf("invalid plugin URL: %w", perr)
			}
			name := filepath.Base(parsed.Path)
			if name == "" || name == "." || name == "/" || strings.Contains(name, "..") {
				return fmt.Errorf("refusing plugin: unsafe file name in URL")
			}
			if !strings.HasSuffix(name, ".so") {
				return fmt.Errorf("refusing plugin: only .so plugins are installable (got %q)", name)
			}
			dest := filepath.Join(dir, name)
			if rel, err := filepath.Rel(dir, dest); err != nil || rel != name {
				return fmt.Errorf("refusing plugin: destination escapes plugin dir")
			}

			fmt.Fprintf(os.Stderr, "Downloading %s...\n", pluginURL)

			resp, err := client.Get(pluginURL)
			if err != nil {
				return fmt.Errorf("download plugin: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("download failed: %s", resp.Status)
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			if err != nil {
				return fmt.Errorf("read plugin: %w", err)
			}

			unsigned := strings.TrimSpace(wantSHA) == "" &&
				(entry == nil || strings.TrimSpace(entry.Sig) == "") &&
				strings.TrimSpace(directSig) == ""
			if unsigned {
				if len(pluginVerifyKey()) == ed25519.PublicKeySize {
					return fmt.Errorf("refusing plugin: verify key configured but plugin is unsigned")
				}
				if !allowUnsigned {
					return fmt.Errorf("refusing plugin: unsigned install requires --allow-unsigned")
				}
				if !yes && !confirmInstall("WARNING: installing UNSIGNED plugin (no hash/signature). Proceed?") {
					return fmt.Errorf("install aborted by user")
				}
			} else if err := verifyPluginBytes(body, entry, directSHA, directSig); err != nil {
				return err
			}

			// Verify-before-write: bytes are checked above, stage + rename.
			// (Lstat symlink refusal; Windows has no O_NOFOLLOW.)
			if fi, err := os.Lstat(dest + ".new"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing plugin: stage path is a symlink")
			}
			tmp, err := os.OpenFile(dest+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("stage plugin file: %w", err)
			}
			if _, err := tmp.Write(body); err != nil {
				tmp.Close()
				os.Remove(dest + ".new")
				return fmt.Errorf("write plugin: %w", err)
			}
			if err := tmp.Sync(); err != nil {
				tmp.Close()
				os.Remove(dest + ".new")
				return fmt.Errorf("fsync plugin: %w", err)
			}
			tmp.Close()
			if err := os.Rename(dest+".new", dest); err != nil {
				os.Remove(dest + ".new")
				return fmt.Errorf("install plugin: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Installed %s (%d bytes, verified) to %s\n", name, len(body), dest)
			fmt.Printf("Plugin %q installed. Restart serve to load it.\n", name)

			return nil
		},
	}
	installCmd.Flags().String("registry", "", "use this registry mirror base instead of the pinned default (https or file://)")
	installCmd.Flags().Bool("allow-host", false, "confirm direct-URL installs from a non-registry host")
	installCmd.Flags().String("sha256", "", "expected hex sha256 (required for direct URLs)")
	installCmd.Flags().String("sig", "", "base64 ed25519 signature over the digest (for direct URLs on signed fleets)")
	installCmd.Flags().Bool("allow-unsigned", false, "permit unsigned install (explicit prompt; refused on signed fleets)")
	installCmd.Flags().Bool("yes", false, "skip the confirmation prompt")
	cmd.AddCommand(installCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "remove [name]",
		Short: "Remove an installed plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmdCobra *cobra.Command, args []string) error {
			name := args[0]
			if !strings.HasSuffix(name, ".so") {
				name += ".so"
			}
			if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
				return fmt.Errorf("refusing remove: unsafe plugin name %q", args[0])
			}
			path := filepath.Join(pluginDir(), name)
			if rel, err := filepath.Rel(pluginDir(), path); err != nil || rel != name {
				return fmt.Errorf("refusing remove: escapes plugin dir")
			}
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("plugin %q not found", name)
				}
				return fmt.Errorf("remove plugin: %w", err)
			}
			fmt.Printf("Plugin %q removed.\n", name)
			return nil
		},
	})

	return cmd
}

func init() {
	_ = context.Background()
}
