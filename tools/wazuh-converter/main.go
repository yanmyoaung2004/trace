package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CLI flags: -in <ruleset root> -out <repo root>. Both default to the
// historical layout (ruleset checkout next to the repo) but no path is
// absolute or machine-specific anymore. -verify checks ruleset.lock
// without writing outputs (CI gate). -write=false + -verify is the
// reproducible check: same inputs => same bytes.
var (
	flagIn     = flag.String("in", "", "wazuh ruleset root (contains rules/ decoders/ lists/ mitre/ rootcheck/ sca/)")
	flagOut    = flag.String("out", "", "repo root output base (generated files land under internal/...)")
	flagVerify = flag.Bool("verify", false, "verify outputs against ruleset.lock + regenerate and diff (no writes)")
)

func rulesetRoot() string {
	if *flagIn != "" {
		return *flagIn
	}
	if v := strings.TrimSpace(os.Getenv("WAZUH_RULESET_DIR")); v != "" {
		return v
	}
	// Historical default: ruleset extracted next to the checkout.
	return filepath.Join(os.TempDir(), "wazuh-rules", "ruleset")
}

func repoRoot() string {
	if *flagOut != "" {
		return *flagOut
	}
	if v := strings.TrimSpace(os.Getenv("TRACE_REPO_ROOT")); v != "" {
		return v
	}
	// tools/wazuh-converter -> repo root (two levels up).
	if exe, err := os.Executable(); err == nil {
		_ = exe
	}
	abs, err := filepath.Abs(filepath.Join("tools", "wazuh-converter"))
	if err == nil {
		if _, err := os.Stat(abs); err == nil {
			if up, err := filepath.Abs("."); err == nil {
				return up
			}
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	// Walk up until go.mod is found (repo root), else use cwd.
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return wd
		}
		dir = parent
	}
}

// lockEntry pins one input file (sha256) so CI can prove the ruleset is
// the reviewed one. ruleset.lock lives next to main.go and is committed.
type lockEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func loadLock(converterDir string) ([]lockEntry, error) {
	raw, err := os.ReadFile(filepath.Join(converterDir, "ruleset.lock"))
	if err != nil {
		return nil, err
	}
	var entries []lockEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func hashFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func converterDir() string {
	return filepath.Join(repoRoot(), "tools", "wazuh-converter")
}

// writeOutput writes data to path, or in -verify mode diffs against the
// existing file and records drift. Returns true when drift was found.
func writeOutput(path string, data []byte, drift *[]string) error {
	if *flagVerify {
		existing, err := os.ReadFile(path)
		if err != nil {
			*drift = append(*drift, path+" (missing)")
			return nil
		}
		if string(existing) != string(data) {
			*drift = append(*drift, path+" (content differs)")
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// verifyLock checks every locked input file still hashes to the pinned
// value. Missing lock file fails closed in -verify mode (CI must review
// the ruleset before pinning); in normal mode it warns once.
func verifyLock(root string) error {
	entries, err := loadLock(converterDir())
	if err != nil {
		if *flagVerify {
			return fmt.Errorf("ruleset.lock missing/unreadable: %w (pin the reviewed ruleset first)", err)
		}
		fmt.Fprintln(os.Stderr, "Warning: no ruleset.lock; outputs unpinned (run with -verify in CI after pinning).")
		return nil
	}
	var bad []string
	for _, e := range entries {
		got, err := hashFile(filepath.Join(root, filepath.FromSlash(e.Path)))
		if err != nil || got != strings.ToLower(e.SHA256) {
			bad = append(bad, e.Path)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("ruleset.lock mismatch (%d files): %s", len(bad), strings.Join(bad, ", "))
	}
	return nil
}

type WazuhDecoderDef struct {
	Name        string `xml:"name,attr"`
	Parent      string `xml:"parent"`
	ProgramName string `xml:"program_name"`
	PreMatch    string `xml:"prematch"`
	Regex       string `xml:"regex"`
	Order       string `xml:"order"`
}

type WazuhDecoderGroup struct {
	XMLName  xml.Name          `xml:"decoder"`
	Decoders []WazuhDecoderDef `xml:"decoder"`
	Name     string            `xml:"name,attr"`
	Parent   string            `xml:"parent,attr"`
	Program  string            `xml:"program_name"`
	PreMatch string            `xml:"prematch"`
	Regex    string            `xml:"regex"`
	Order    string            `xml:"order"`
}

type DecoderEntry struct {
	Name        string   `json:"name"`
	Parent      string   `json:"parent,omitempty"`
	ProgramName string   `json:"program_name,omitempty"`
	PreMatch    string   `json:"prematch,omitempty"`
	Regex       string   `json:"regex,omitempty"`
	Order       []string `json:"order,omitempty"`
}

func convertDecoders(root, outBase string, drift *[]string) {
	decodersDir := filepath.Join(root, "decoders")
	outputPath := filepath.Join(outBase, "internal", "siem", "wazuh_decoders_gen.go")

	var allDecoders []DecoderEntry

	files, _ := os.ReadDir(decodersDir)
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".xml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(decodersDir, f.Name()))
		if err != nil {
			continue
		}

		content := string(data)
		decoderTags := extractDecoderTags(content)

		for _, xmlStr := range decoderTags {
			var d WazuhDecoderDef
			if err := xml.Unmarshal([]byte(xmlStr), &d); err != nil {
				continue
			}
			if d.Name == "" {
				continue
			}
			if d.Regex == "" && d.PreMatch == "" && d.ProgramName == "" {
				continue
			}
			entry := DecoderEntry{
				Name:        d.Name,
				Parent:      d.Parent,
				ProgramName: d.ProgramName,
				PreMatch:    d.PreMatch,
				Regex:       d.Regex,
			}
			if d.Order != "" {
				entry.Order = strings.Split(d.Order, "|")
			}
			allDecoders = append(allDecoders, entry)
		}
	}

	fmt.Printf("Converted %d decoders from %d files\n", len(allDecoders), len(files))

	sort.Slice(allDecoders, func(i, j int) bool {
		if allDecoders[i].Name == allDecoders[j].Name {
			return allDecoders[i].Parent < allDecoders[j].Parent
		}
		return allDecoders[i].Name < allDecoders[j].Name
	})
	jsonData, _ := json.Marshal(allDecoders)
	var goBuf strings.Builder
	goBuf.WriteString("package siem\n\n")
	goBuf.WriteString("// Code generated by tools/wazuh-converter. DO NOT EDIT.\n")
	goBuf.WriteString("var wazuhDecodersJSON = `")
	goBuf.WriteString(string(jsonData))
	goBuf.WriteString("`\n")

	if err := writeOutput(outputPath, []byte(goBuf.String()), drift); err != nil {
		fmt.Fprintf(os.Stderr, "write decoders: %v\n", err)
		return
	}
	fmt.Printf("Written to %s\n", outputPath)
}

func extractDecoderTags(content string) []string {
	var tags []string
	start := 0
	for {
		openIdx := strings.Index(content[start:], "<decoder ")
		if openIdx < 0 {
			openIdx = strings.Index(content[start:], "<decoder>")
		}
		if openIdx < 0 {
			break
		}
		openIdx += start

		closeIdx := strings.Index(content[openIdx:], "</decoder>")
		if closeIdx < 0 {
			break
		}
		closeIdx += openIdx + len("</decoder>")

		tags = append(tags, content[openIdx:closeIdx])
		start = closeIdx
	}
	return tags
}

func convertLists(root, outBase string, drift *[]string) {
	listsDir := filepath.Join(root, "lists")
	outputPath := filepath.Join(outBase, "internal", "siem", "wazuh_lists_gen.go")

	data := make(map[string]map[string]string)

	filepath.Walk(listsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(listsDir, path)
		name := strings.ReplaceAll(rel, "\\", "_")
		name = strings.ReplaceAll(name, "/", "_")
		name = strings.TrimSuffix(name, filepath.Ext(name))

		entries := make(map[string]string)
		content, _ := os.ReadFile(path)
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "TEMPLATE:") || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				entries[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			} else {
				entries[line] = ""
			}
		}
		if len(entries) > 0 {
			data[name] = entries
		}
		return nil
	})

	jsonData, _ := json.Marshal(data)
	var buf strings.Builder
	buf.WriteString("package siem\n\n")
	buf.WriteString("// Code generated by tools/wazuh-converter. DO NOT EDIT.\n")
	buf.WriteString("var wazuhListsJSON = `")
	buf.WriteString(string(jsonData))
	buf.WriteString("`\n")

	if err := writeOutput(outputPath, []byte(buf.String()), drift); err != nil {
		fmt.Fprintf(os.Stderr, "write lists: %v\n", err)
		return
	}
	fmt.Printf("Converted %d lists to %s\n", len(data), outputPath)
}

func convertMitre(root, outBase string, drift *[]string) {
	inputPath := filepath.Join(root, "mitre", "enterprise-attack.json")
	outputPath := filepath.Join(outBase, "internal", "archive", "mitre_seed_gen.go")

	data, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read mitre: %v\n", err)
		return
	}

	var bundle struct {
		Objects []struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Name      string `json:"name"`
			Created   string `json:"created"`
			Modified  string `json:"modified"`
			Description string `json:"description"`
			KillChainPhases []struct {
				PhaseName string `json:"phase_name"`
			} `json:"kill_chain_phases"`
			ExternalRefs []struct {
				Source   string `json:"source_name"`
				ExternalID string `json:"external_id"`
			} `json:"external_references"`
			Platforms []string `json:"x_mitre_platforms"`
			Detection    string `json:"x_mitre_detection"`
		} `json:"objects"`
	}

	if err := json.Unmarshal(data, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "parse mitre: %v\n", err)
		return
	}

	tacticShort := make(map[string]string)
	mitreID := make(map[string]string)
	mitigations := make(map[string]string)

	for _, obj := range bundle.Objects {
		if obj.Type == "x-mitre-tactic" {
			for _, r := range obj.ExternalRefs {
				if r.Source == "mitre-attack" && r.ExternalID != "" {
					tacticShort[r.ExternalID] = obj.Name
				}
			}
		}
	}

	for _, obj := range bundle.Objects {
		if obj.Type == "course-of-action" {
			for _, r := range obj.ExternalRefs {
				if r.Source == "mitre-attack" && r.ExternalID != "" {
					mitreID[r.ExternalID] = obj.ID
					mitigations[r.ExternalID] = obj.Name
				}
			}
		}
	}

	type Technique struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tactics     []string `json:"tactics"`
		Platforms   []string `json:"platforms"`
		Mitigations []string `json:"mitigations"`
		Detection   []string `json:"detection"`
	}

	var techniques []Technique
	seen := make(map[string]bool)

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}
		var mitreAttackID string
		for _, r := range obj.ExternalRefs {
			if r.Source == "mitre-attack" {
				mitreAttackID = r.ExternalID
			}
			if r.Source == "mitre-attack" && strings.HasPrefix(r.ExternalID, "T") {
				mitreAttackID = r.ExternalID
			}
		}
		if mitreAttackID == "" || seen[mitreAttackID] {
			continue
		}
		seen[mitreAttackID] = true

		var tactics []string
		for _, kcp := range obj.KillChainPhases {
			tactics = append(tactics, kcp.PhaseName)
		}

		fullTactics := make([]string, 0, len(tactics))
		for _, t := range tactics {
			if name, ok := tacticShort[t]; ok {
				fullTactics = append(fullTactics, name)
			} else {
				fullTactics = append(fullTactics, t)
			}
		}

		var mitigationNames []string
		for _, ref := range obj.ExternalRefs {
			if ref.Source == "mitre-attack" {
				if m, ok := mitigations[ref.ExternalID]; ok {
					mitigationNames = append(mitigationNames, m)
				}
			}
		}

		var detection []string
		if obj.Detection != "" {
			detection = append(detection, obj.Detection)
		}

		techniques = append(techniques, Technique{
			ID:          mitreAttackID,
			Name:        obj.Name,
			Description: obj.Description,
			Tactics:     fullTactics,
			Platforms:   obj.Platforms,
			Mitigations: mitigationNames,
			Detection:   detection,
		})
	}

	sort.Slice(techniques, func(i, j int) bool { return techniques[i].ID < techniques[j].ID })
	jsonData, _ := json.Marshal(techniques)
	escaped := strings.ReplaceAll(string(jsonData), "`", "` + \"`\" + `")
	var buf strings.Builder
	buf.WriteString("package archive\n\n")
	buf.WriteString("// Code generated by tools/wazuh-converter. DO NOT EDIT.\n")
	buf.WriteString("var mitreSeedJSON = `")
	buf.WriteString(escaped)
	buf.WriteString("`\n")

	if err := writeOutput(outputPath, []byte(buf.String()), drift); err != nil {
		fmt.Fprintf(os.Stderr, "write mitre: %v\n", err)
		return
	}
	fmt.Printf("Converted %d MITRE techniques to %s\n", len(techniques), outputPath)
}

func convertRootkits(root, outBase string, drift *[]string) {
	rootcheckDir := filepath.Join(root, "rootcheck", "db")
	outputPath := filepath.Join(outBase, "internal", "sift", "rootkit_gen.go")

	type rootkitEntry struct {
		Pattern string `json:"pattern"`
		Name    string `json:"name"`
		Ref     string `json:"ref"`
	}

	type trojanEntry struct {
		Binary      string `json:"binary"`
		Signature   string `json:"signature"`
		Description string `json:"description"`
	}

	var rootkits []rootkitEntry
	var trojans []trojanEntry

	// Parse rootkit_files.txt
	if data, err := os.ReadFile(filepath.Join(rootcheckDir, "rootkit_files.txt")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "!", 3)
			if len(parts) >= 2 {
				entry := rootkitEntry{
					Pattern: strings.TrimSpace(parts[0]),
					Name:    strings.TrimSpace(parts[1]),
				}
				if len(parts) >= 3 {
					entry.Ref = strings.TrimSpace(strings.TrimPrefix(parts[2], "::"))
				}
				rootkits = append(rootkits, entry)
			}
		}
	}

	// Parse rootkit_trojans.txt
	if data, err := os.ReadFile(filepath.Join(rootcheckDir, "rootkit_trojans.txt")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "!", 3)
			if len(parts) >= 3 {
				trojans = append(trojans, trojanEntry{
					Binary:      strings.TrimSpace(parts[0]),
					Signature:   strings.TrimSpace(parts[1]),
					Description: strings.TrimSpace(parts[2]),
				})
			}
		}
	}

	sort.Slice(rootkits, func(i, j int) bool {
		if rootkits[i].Pattern == rootkits[j].Pattern {
			return rootkits[i].Name < rootkits[j].Name
		}
		return rootkits[i].Pattern < rootkits[j].Pattern
	})
	sort.Slice(trojans, func(i, j int) bool {
		if trojans[i].Binary == trojans[j].Binary {
			return trojans[i].Signature < trojans[j].Signature
		}
		return trojans[i].Binary < trojans[j].Binary
	})
	rkJSON, _ := json.Marshal(rootkits)
	tjJSON, _ := json.Marshal(trojans)

	escRK := strings.ReplaceAll(string(rkJSON), "`", "` + \"`\" + `")
	escTJ := strings.ReplaceAll(string(tjJSON), "`", "` + \"`\" + `")

	var buf strings.Builder
	buf.WriteString("package sift\n\n")
	buf.WriteString("// Code generated by tools/wazuh-converter. DO NOT EDIT.\n\n")
	buf.WriteString("var rootkitFilesJSON = `")
	buf.WriteString(escRK)
	buf.WriteString("`\n\n")
	buf.WriteString("var rootkitTrojanJSON = `")
	buf.WriteString(escTJ)
	buf.WriteString("`\n")

	if err := writeOutput(outputPath, []byte(buf.String()), drift); err != nil {
		fmt.Fprintf(os.Stderr, "write rootkits: %v\n", err)
		return
	}
	fmt.Printf("Converted %d rootkit files and %d trojan signatures\n", len(rootkits), len(trojans))
}

func convertSCA(root, outBase string, drift *[]string) {
	scaDir := filepath.Join(root, "sca")
	outputPath := filepath.Join(outBase, "internal", "plugins", "sca", "policies_gen.go")
	type policyEntry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Data string `json:"data"`
	}

	var policies []policyEntry

	filepath.Walk(scaDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(scaDir, path)
		id := strings.TrimSuffix(filepath.Base(path), ".yml")
		name := strings.TrimSuffix(rel, ".yml")

		escaped := strings.ReplaceAll(string(data), "`", "` + \"`\" + `")
		policies = append(policies, policyEntry{ID: id, Name: name, Data: escaped})
		return nil
	})

	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	jsonData, _ := json.Marshal(policies)
	escaped := strings.ReplaceAll(string(jsonData), "`", "` + \"`\" + `")

	var buf strings.Builder
	buf.WriteString("package sca\n\n")
	buf.WriteString("// Code generated by tools/wazuh-converter. DO NOT EDIT.\n\n")
	buf.WriteString("var policiesJSON = `")
	buf.WriteString(escaped)
	buf.WriteString("`\n")

	if err := writeOutput(outputPath, []byte(buf.String()), drift); err != nil {
		fmt.Fprintf(os.Stderr, "write sca: %v\n", err)
		return
	}
	fmt.Printf("Converted %d SCA policies to %s\n", len(policies), outputPath)
}

type WazuhRule struct {
	XMLName     xml.Name `xml:"rule"`
	ID          string   `xml:"id,attr"`
	Level       string   `xml:"level,attr"`
	Frequency   string   `xml:"frequency,attr"`
	Timeframe   string   `xml:"timeframe,attr"`
	NoAlert     string   `xml:"noalert,attr"`
	Match       string   `xml:"match"`
	Regex       string   `xml:"regex"`
	Description string   `xml:"description"`
	Group       string   `xml:"group"`
	IfSID       string   `xml:"if_sid"`
	IfMatchedSID string  `xml:"if_matched_sid"`
	SameSourceIP string  `xml:"same_source_ip"`
	SameUser    string   `xml:"same_user"`
	SameLocation string  `xml:"same_location"`
	Mitre       struct {
		IDs []string `xml:"id"`
	} `xml:"mitre"`
	DecodedAs string `xml:"decoded_as"`
	Field     string `xml:"field"`
}

type WazuhGroup struct {
	XMLName xml.Name    `xml:"group"`
	Name    string      `xml:"name,attr"`
	Rules   []WazuhRule `xml:"rule"`
}

type OutputRule struct {
	RuleID      string            `yaml:"rule_id"`
	Description string            `yaml:"description"`
	Severity    int               `yaml:"severity"`
	MITRE       string            `yaml:"mitre,omitempty"`
	Condition   string            `yaml:"condition"`
	WindowDur   string            `yaml:"window,omitempty"`
	Threshold   int               `yaml:"threshold,omitempty"`
	Playbook    string            `yaml:"playbook,omitempty"`
	PlaybookParams map[string]string `yaml:"params,omitempty"`
}

func mapPlaybook(mitreIDs string, severity int, desc string) (string, map[string]string) {
	mitreList := strings.Split(mitreIDs, ",")
	for _, m := range mitreList {
		m = strings.TrimSpace(m)
		switch m {
		case "T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004":
			return "ip-reputation", map[string]string{"ip": "${source_ip}"}
		case "T1190", "T1133":
			return "ip-reputation", map[string]string{"ip": "${source_ip}"}
		case "T1204", "T1204.002":
			return "file-analysis", map[string]string{"path": "${file_path}"}
		case "T1566", "T1566.001", "T1566.002", "T1566.003":
			return "email-analysis", map[string]string{"sender_ip": "${source_ip}", "subject": "${subject}"}
		case "T1059", "T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007":
			return "log-analysis", map[string]string{"event_id": "${event_id}"}
		case "T1547", "T1547.001":
			return "registry-check", map[string]string{"registry_key": "${registry_key}"}
		case "T1543", "T1543.003":
			return "file-analysis", map[string]string{"path": "${file_path}"}
		case "T1053", "T1053.005":
			return "file-analysis", map[string]string{"path": "${file_path}"}
		case "T1003":
			return "file-analysis", map[string]string{"hash": "${hash}"}
		case "T1021", "T1021.001", "T1021.002":
			return "ip-reputation", map[string]string{"ip": "${source_ip}"}
		case "T1071", "T1071.001":
			return "domain-reputation", map[string]string{"domain": "${domain}"}
		case "T1562", "T1562.001":
			return "file-analysis", map[string]string{"path": "${file_path}"}
		case "T1078", "T1078.003":
			return "ip-reputation", map[string]string{"ip": "${source_ip}"}
		}
	}

	descLower := strings.ToLower(desc)
	switch {
	case strings.Contains(descLower, "ssh") && strings.Contains(descLower, "brute"):
		return "ip-reputation", map[string]string{"ip": "${source_ip}"}
	case strings.Contains(descLower, "mail") && strings.Contains(descLower, "virus"):
		return "email-analysis", map[string]string{}
	case strings.Contains(descLower, "rootkit"):
		return "rootkit-scan", map[string]string{}
	case strings.Contains(descLower, "compliance") || strings.Contains(descLower, "cis "):
		return "compliance-scan", map[string]string{}
	case strings.Contains(descLower, "malware") || strings.Contains(descLower, "virus"):
		return "file-analysis", map[string]string{}
	case strings.Contains(descLower, "firewall") || strings.Contains(descLower, "blocked"):
		return "ip-reputation", map[string]string{"ip": "${source_ip}"}
	case severity >= 10:
		return "full-enrich", map[string]string{"indicator": "${srcip}"}
	}

	if severity >= 8 {
		return "full-enrich", map[string]string{"indicator": "${srcip}"}
	}
	return "", nil
}

var severityNames = map[int]string{
	0:  "disabled",
	1:  "info",
	2:  "low",
	3:  "low",
	4:  "medium",
	5:  "medium",
	6:  "medium",
	7:  "high",
	8:  "high",
	9:  "critical",
	10: "critical",
	12: "critical",
	13: "critical",
	14: "critical",
	15: "critical",
}

func convertRule(r WazuhRule) *OutputRule {
	if r.NoAlert == "1" || r.Level == "0" {
		return nil
	}

	level, _ := strconv.Atoi(r.Level)
	if level < 3 {
		return nil
	}

	if r.Match == "" && r.Regex == "" {
		return nil
	}

	if r.IfSID != "" && r.Match == "" && r.Regex == "" && r.Frequency == "" {
		return nil
	}

	condition := ""
	val := r.Match
	if val == "" {
		val = r.Regex
	}
	if val != "" {
		val = strings.ReplaceAll(val, `\`, `\\`)
		val = strings.ReplaceAll(val, `"`, `\"`)

		if strings.HasPrefix(val, `^`) {
			condition = `field:message ~= ` + val
		} else if r.Match != "" {
			condition = `field:message ~= (?i)` + regexp.QuoteMeta(r.Match)
		} else {
			condition = `field:message ~= ` + val
		}
	}

	if r.DecodedAs != "" {
		condition = "tag:" + r.DecodedAs
		if val != "" {
		}
	}

	windowDur := ""
	threshold := 0
	if r.Frequency != "" {
		threshold, _ = strconv.Atoi(r.Frequency)
		if threshold < 2 {
			threshold = 2
		}
	}
	if r.Timeframe != "" {
		tf := strings.TrimSuffix(r.Timeframe, "s")
		if secs, err := strconv.Atoi(tf); err == nil {
			windowDur = fmt.Sprintf("%d * time.Second", secs)
		} else {
			windowDur = r.Timeframe + " * time.Second"
		}
	}
	if threshold > 0 && windowDur == "" {
		windowDur = "3600 * time.Second"
	}

	mitreIDs := ""
	if len(r.Mitre.IDs) > 0 {
		mitreIDs = strings.Join(r.Mitre.IDs, ",")
	}

	desc := strings.TrimSpace(r.Description)
	if desc == "" {
		desc = "Wazuh rule " + r.ID
	}

	pb, pbParams := mapPlaybook(mitreIDs, level, desc)

	return &OutputRule{
		RuleID:      "WAZUH_" + r.ID,
		Description: desc,
		Severity:    level,
		MITRE:       mitreIDs,
		Condition:   condition,
		WindowDur:   windowDur,
		Threshold:   threshold,
		Playbook:    pb,
		PlaybookParams: pbParams,
	}
}

func main() {
	flag.Parse()
	root := rulesetRoot()
	outBase := repoRoot()
	rulesDir := filepath.Join(root, "rules")
	outputDir := filepath.Join(outBase, "internal", "siem")

	fmt.Printf("Ruleset: %s\nOutput:  %s\n", root, outBase)
	if st, err := os.Stat(rulesDir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "rules dir not found: %s (pass -in <ruleset root> or set WAZUH_RULESET_DIR)\n", rulesDir)
		os.Exit(1)
	}

	if err := verifyLock(root); err != nil {
		fmt.Fprintf(os.Stderr, "ruleset lock: %v\n", err)
		os.Exit(1)
	}

	var drift []string

	type namedRules struct {
		name  string
		rules []OutputRule
	}

	var allRuleSets []namedRules
	totalConverted := 0
	totalSkipped := 0

	files, _ := os.ReadDir(rulesDir)
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".xml" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(rulesDir, f.Name()))
		if err != nil {
			continue
		}

		content := string(data)

		if !strings.Contains(content, "<group ") && !strings.Contains(content, "<rule ") {
			continue
		}

		var group WazuhGroup
		if err := xml.Unmarshal(data, &group); err != nil {
			var single WazuhRule
			if err := xml.Unmarshal(data, &single); err != nil {
				continue
			}
			group.Rules = []WazuhRule{single}
		}

		var converted []OutputRule
		for _, rule := range group.Rules {
			out := convertRule(rule)
			if out != nil {
				converted = append(converted, *out)
				totalConverted++
			} else {
				totalSkipped++
			}
		}

		if len(converted) > 0 {
			// Deterministic within a file: sort by RuleID.
			sort.Slice(converted, func(i, j int) bool { return converted[i].RuleID < converted[j].RuleID })
			allRuleSets = append(allRuleSets, namedRules{name: f.Name(), rules: converted})
		}
	}

	sort.Slice(allRuleSets, func(i, j int) bool {
		return allRuleSets[i].name < allRuleSets[j].name
	})

	fmt.Printf("Total Wazuh rules parsed: %d\n", totalConverted+totalSkipped)
	fmt.Printf("Converted: %d\n", totalConverted)
	fmt.Printf("Skipped (low/no match/no alert): %d\n", totalSkipped)
	fmt.Printf("Rule sets: %d\n", len(allRuleSets))

	var goBuf strings.Builder
	goBuf.WriteString("package siem\n\n")
	goBuf.WriteString("// Code generated by tools/wazuh-converter. DO NOT EDIT.\n")
	goBuf.WriteString("// Source ruleset pinned in tools/wazuh-converter/ruleset.lock.\n")
	goBuf.WriteString("import \"time\"\n\n")
	goBuf.WriteString("func loadWazuhRules() []CompiledRule {\n")
	goBuf.WriteString("\treturn []CompiledRule{\n")

	ruleCount := 0
	for _, rs := range allRuleSets {
		for _, r := range rs.rules {
			ruleCount++
			goBuf.WriteString(fmt.Sprintf("\t\t{\n"))
			goBuf.WriteString(fmt.Sprintf("\t\t\tRuleID:      %q,\n", r.RuleID))
			goBuf.WriteString(fmt.Sprintf("\t\t\tDescription: %q,\n", r.Description))
			goBuf.WriteString(fmt.Sprintf("\t\t\tSeverity:    %d,\n", r.Severity))

			if r.MITRE != "" {
				goBuf.WriteString(fmt.Sprintf("\t\t\tMITRE:       %q,\n", r.MITRE))
			}

			cond := r.Condition
			cond = strings.ReplaceAll(cond, `\\`, `\`)
			cond = strings.ReplaceAll(cond, `\"`, `"`)
			if cond != "" {
				goBuf.WriteString(fmt.Sprintf("\t\t\tcondition:   %q,\n", cond))
			}

			if r.Threshold > 0 {
				goBuf.WriteString(fmt.Sprintf("\t\t\tthreshold:   %d,\n", r.Threshold))
			}
			if r.WindowDur != "" {
				goBuf.WriteString(fmt.Sprintf("\t\t\twindowDur:   %s,\n", r.WindowDur))
			}

			if r.Playbook != "" {
				goBuf.WriteString(fmt.Sprintf("\t\t\tActions:     []RuleAction{{Playbook: %q, Params: map[string]any{", r.Playbook))
				keys := make([]string, 0, len(r.PlaybookParams))
				for k := range r.PlaybookParams {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				first := true
				for _, k := range keys {
					if !first {
						goBuf.WriteString(", ")
					}
					goBuf.WriteString(fmt.Sprintf("%q: %q", k, r.PlaybookParams[k]))
					first = false
				}
				goBuf.WriteString("}}},\n")
			}

			goBuf.WriteString("\t\t},\n")
		}
	}

	goBuf.WriteString("\t}\n")
	goBuf.WriteString("}\n")

	outPath := filepath.Join(outputDir, "wazuh_rules_gen.go")
	if err := writeOutput(outPath, []byte(goBuf.String()), &drift); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nGenerated %s with %d rules\n", outPath, ruleCount)

	convertDecoders(root, outBase, &drift)
	convertLists(root, outBase, &drift)
	convertMitre(root, outBase, &drift)
	convertRootkits(root, outBase, &drift)
	convertSCA(root, outBase, &drift)

	if *flagVerify {
		if err := verifyLock(root); err != nil {
			fmt.Fprintf(os.Stderr, "verify: %v\n", err)
			os.Exit(1)
		}
		if len(drift) > 0 {
			fmt.Fprintf(os.Stderr, "verify: %d generated files differ (regenerate with the pinned ruleset):\n", len(drift))
			for _, d := range drift {
				fmt.Fprintf(os.Stderr, "  - %s\n", d)
			}
			os.Exit(1)
		}
		fmt.Println("verify: generated files match the pinned ruleset.")
	}
}
