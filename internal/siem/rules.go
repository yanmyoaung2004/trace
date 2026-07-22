package siem

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var embeddedRuleFS embed.FS

type RuleSet struct {
	Name     string
	Rules    []CompiledRule
}

type CompiledRule struct {
	RuleID      string
	Description string
	Severity    int
	MITRE       string
	Compliance  map[string][]string
	Actions     []RuleAction

	condition string
	field     string
	operator  string
	value     string
	re        *regexp.Regexp
	windowDur time.Duration
	suppress  time.Duration
	threshold int
}

type RuleAction struct {
	Playbook string
	Params   map[string]any
}

type RuleEngine struct {
	rules     []CompiledRule
	mu        sync.RWMutex

	correlation   map[string][]time.Time
	correlationMu sync.Mutex

	suppression   map[string]time.Time
	suppressionMu sync.Mutex
}

func NewRuleEngine() *RuleEngine {
	re := &RuleEngine{
		correlation: make(map[string][]time.Time),
		suppression: make(map[string]time.Time),
	}
	re.LoadDefault()
	if err := re.LoadBuiltinYAML(); err != nil {
		fmt.Printf("[siem] warning: builtin YAML rules: %v\n", err)
	}
	return re
}

type YAMLRule struct {
	RuleID      string            `yaml:"rule_id"`
	Description string            `yaml:"description"`
	Severity    int               `yaml:"severity"`
	MITRE       string            `yaml:"mitre,omitempty"`
	Condition   string            `yaml:"condition"`
	WindowDur   string            `yaml:"window,omitempty"`
	Threshold   int               `yaml:"threshold,omitempty"`
	Suppress    string            `yaml:"suppress,omitempty"`
	Playbook    string            `yaml:"playbook,omitempty"`
	Params      map[string]string `yaml:"params,omitempty"`
}

type YAMLRuleFile struct {
	Rules []YAMLRule `yaml:"rules"`
}

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err == nil {
		return d
	}
	return 0
}

func (re *RuleEngine) LoadYAML(data []byte) error {
	var file YAMLRuleFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	re.mu.Lock()
	defer re.mu.Unlock()
	for _, yr := range file.Rules {
		cr := CompiledRule{
			RuleID:      yr.RuleID,
			Description: yr.Description,
			Severity:    yr.Severity,
			MITRE:       yr.MITRE,
			condition:   yr.Condition,
			windowDur:   parseDuration(yr.WindowDur),
			threshold:   yr.Threshold,
			suppress:    parseDuration(yr.Suppress),
		}
		if yr.Playbook != "" {
			params := make(map[string]any)
			for k, v := range yr.Params {
				params[k] = v
			}
			cr.Actions = []RuleAction{{Playbook: yr.Playbook, Params: params}}
		}
		re.rules = append(re.rules, cr)
	}
	return nil
}

func (re *RuleEngine) LoadBuiltinYAML() error {
	entries, err := embeddedRuleFS.ReadDir("rules")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := embeddedRuleFS.ReadFile("rules/" + e.Name())
		if err != nil {
			return fmt.Errorf("read builtin %s: %w", e.Name(), err)
		}
		if err := re.LoadYAML(data); err != nil {
			return fmt.Errorf("load builtin %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (re *RuleEngine) LoadYAMLDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		if err := re.LoadYAML(data); err != nil {
			return fmt.Errorf("load %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (re *RuleEngine) LoadDefault() {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.rules = loadWazuhRules()
	re.rules = append(re.rules, builtinRules()...)

	for i := range re.rules {
		re.rules[i].Compliance = mapCompliance(re.rules[i].MITRE, re.rules[i].Severity, re.rules[i].Description)
	}

	fmt.Printf("[siem] loaded %d external + %d built-in rules\n", len(loadWazuhRules()), len(builtinRules()))
}

func mapCompliance(mitre string, severity int, description string) map[string][]string {
	c := make(map[string][]string)

	if mitre == "" && severity == 0 {
		return c
	}

	mitreIDs := strings.Split(mitre, ",")
	for _, m := range mitreIDs {
		m = strings.TrimSpace(m)
		switch m {
		// === Brute Force / Credential Access ===
		case "T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["pci_dss_v3.2.1"] = append(c["pci_dss_v3.2.1"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-7", "IA-5")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.9.2.1", "A.9.4.2")
			c["soc_2"] = append(c["soc_2"], "CC6.1")

		// === Exploit Public-Facing App / External Remote Services ===
		case "T1190", "T1133":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.2.5", "6.2")
			c["pci_dss_v3.2.1"] = append(c["pci_dss_v3.2.1"], "1.2.1", "6.2")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(e)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-17", "SC-7")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.13.1.1")
			c["soc_2"] = append(c["soc_2"], "CC6.6")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "4.8")

		// === Phishing ===
		case "T1566", "T1566.001", "T1566.002", "T1566.003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.308(a)(1)(i)", "164.308(a)(5)(i)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "SI-2")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.7.2.2")

		// === Execution / Command & Scripting ===
		case "T1059", "T1059.001", "T1059.003", "T1059.005", "T1059.006", "T1059.007":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.4.1", "2.2.4")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)", "164.312(a)(2)(iv)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-3", "CM-7(5)")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.12.5.1", "A.12.14.1")
			c["soc_2"] = append(c["soc_2"], "CC6.8")

		// === User Execution / Malware ===
		case "T1204", "T1204.002":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.2")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)", "164.310(d)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "10.5")

		// === Boot/Logon Autostart Execution ===
		case "T1547", "T1547.001":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "2.2.4")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)", "164.310(d)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CM-7(5)", "SI-16")

		// === Create or Modify System Process / Service ===
		case "T1543", "T1543.003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "2.2.4")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CM-7(5)")
			c["soc_2"] = append(c["soc_2"], "CC6.8")

		// === Scheduled Task ===
		case "T1053", "T1053.005":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.4.1", "2.2.4")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CM-7(5)")

		// === OS Credential Dumping ===
		case "T1003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(a)(2)(iv)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "IA-5", "AC-3")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.9.2.1", "A.9.4.2")

		// === Valid Accounts ===
		case "T1078", "T1078.003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.2.1", "8.3.2")
			c["pci_dss_v3.2.1"] = append(c["pci_dss_v3.2.1"], "8.2.1", "8.3.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "IA-5")
			c["soc_2"] = append(c["soc_2"], "CC6.3")

		// === Disable or Modify Tools / Defense Evasion ===
		case "T1562", "T1562.001":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)", "164.310(d)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")
			c["soc_2"] = append(c["soc_2"], "CC6.8")

		// === Indicator Removal ===
		case "T1070", "T1070.004":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "10.2.1", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(b)", "164.308(a)(1)(ii)(D)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.30")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-3", "AU-12")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.12.4.1")
			c["soc_2"] = append(c["soc_2"], "CC7.1")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "8.8")

		// === Network Service Scanning ===
		case "T1046":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.2.5", "2.2.5")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(e)(1)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "AC-3")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.13.1.3")

		// === Remote Services ===
		case "T1021", "T1021.001", "T1021.002", "T1021.004":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.2.1", "1.2.5")
			c["hipaa"] = append(c["hipaa"], "164.312(e)(1)", "164.312(a)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-17(2)", "SC-8")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "3.10")

		// === Application Layer Protocol ===
		case "T1071", "T1071.001", "T1071.004":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.1", "4.1.1")
			c["hipaa"] = append(c["hipaa"], "164.312(e)(1)", "164.312(e)(2)(ii)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-8", "SC-13")
			c["soc_2"] = append(c["soc_2"], "CC6.6")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "3.10")

		// === Exfiltration Over C2 ===
		case "T1048":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.1", "4.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(e)(1)", "164.312(e)(2)(ii)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.33")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-8", "AU-12")

		// === Inhibit System Recovery ===
		case "T1490":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(2)", "164.308(a)(7)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.33")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-2(2)", "CP-10")
			c["soc_2"] = append(c["soc_2"], "CC7.1")

		// === NEW: C2 Custom Protocol ===
		case "T1095":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.1", "4.1.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-13", "SC-8")

		// === NEW: Rootkit ===
		case "T1014":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.2")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)", "164.310(d)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")

		// === NEW: Application Deployment Software ===
		case "T1072":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.4.1", "2.2.4")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CM-7(5)", "SA-10")
			c["soc_2"] = append(c["soc_2"], "CC6.8")

		// === NEW: File and Directory Discovery ===
		case "T1083":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "2.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "AU-12")

		// === NEW: Office Application Startup ===
		case "T1137":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.2")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CM-7(5)")

		// === NEW: Web Shell ===
		case "T1505.003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "6.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "CM-7(5)")

		// === NEW: Exploitation for Client Execution ===
		case "T1203":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "5.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-2(2)", "SI-16")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "7.3")

		// === NEW: Data from Information Repositories ===
		case "T1213":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.2.1", "4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(e)(2)(ii)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "SC-8")

		// === NEW: Exploitation of Remote Services ===
		case "T1210":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.2.5", "6.2")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(e)(1)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "SI-2(2)")
			c["iso_27001-2013"] = append(c["iso_27001-2013"], "A.13.1.3")

		// === NEW: Exploitation for Privilege Escalation ===
		case "T1068":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "SI-2(2)")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "7.3")

		// === NEW: Steal Web Session Cookie ===
		case "T1539":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "SC-8")

		// === NEW: Data Encrypted for Impact ===
		case "T1486":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(2)", "164.308(a)(7)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.33")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-13", "CP-10")
			c["soc_2"] = append(c["soc_2"], "CC7.1")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "10.5")

		// === NEW: System Shutdown/Reboot ===
		case "T1529":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(2)", "164.308(a)(7)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-2(2)", "CP-10")

		// === NEW: Data Destruction ===
		case "T1485":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(2)", "164.308(a)(7)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.33")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CP-10")

		// === NEW: Account Manipulation ===
		case "T1098", "T1098.001":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.2.1", "6.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(a)(2)(iv)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "IA-5")
			c["soc_2"] = append(c["soc_2"], "CC6.3")

		// === NEW: Email Collection ===
		case "T1114":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.2.1", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(e)(2)(ii)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "SC-8")

		// === NEW: Data Staged ===
		case "T1074":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "2.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-12", "AC-3")

		// === NEW: Indicators of Compromise ===
		case "T1555", "T1555.003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "IA-5", "AC-3")

		// === NEW: Resource Hijacking ===
		case "T1499":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-2(2)", "SC-5")
			c["soc_2"] = append(c["soc_2"], "CC7.1")

		// === NEW: Data Manipulation ===
		case "T1565", "T1565.001":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)", "164.312(c)(2)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "SC-13")
			c["soc_2"] = append(c["soc_2"], "CC7.1")

		// === NEW: Account Discovery ===
		case "T1087":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.2.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-12", "AC-3")

		// === NEW: Network Service Discovery ===
		case "T1049":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.2.5", "2.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "AC-3")

		// === NEW: Wireless ===
		case "T1559":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.4", "4.1.1")
			c["hipaa"] = append(c["hipaa"], "164.312(e)(1)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-8", "SC-13")

		// === NEW: Trusted Relationship ===
		case "T1199":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.2.1", "6.2")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "IA-5")
			c["soc_2"] = append(c["soc_2"], "CC6.3")

		// === NEW: Remote Access Software ===
		case "T1219":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "2.2.5", "1.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-17", "SC-7")
			c["cis_csc_v8"] = append(c["cis_csc_v8"], "4.8")

		// === NEW: Data Compressed ===
		case "T1560":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "10.4.1", "4.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-12")

		// === NEW: Exfiltration Over C2 ===
		case "T1567":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.1", "4.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(e)(1)", "164.312(e)(2)(ii)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.33")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-8", "AU-12")

		// === NEW: Spearphishing via Service ===
		case "T1598":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2")
			c["hipaa"] = append(c["hipaa"], "164.308(a)(5)(i)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-2", "AT-2")

		// === NEW: Disk Content Wipe ===
		case "T1561", "T1561.001":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "10.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(2)", "164.308(a)(7)")
			c["gdpr"] = append(c["gdpr"], "Art.32", "Art.33")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CP-10")

		// === NEW: Steal Application Access Token ===
		case "T1528":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "IA-5")

		// === NEW: Pluggable Authentication Module ===
		case "T1556", "T1556.004":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "CM-7(5)")
			c["soc_2"] = append(c["soc_2"], "CC6.8")

		// === NEW: System Time Discovery ===
		case "T1124":
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-12")

		// === NEW: Virtualization/Sandbox Evasion ===
		case "T1497":
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16")

		// === NEW: Hijack Execution Flow ===
		case "T1574", "T1574.004":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "2.2.4")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")

		// === NEW: System Information Discovery ===
		case "T1082":
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-12")
			c["soc_2"] = append(c["soc_2"], "CC7.1")

		// === NEW: Masquerading ===
		case "T1036":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.4.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")

		// === NEW: Process Injection ===
		case "T1055":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.4.1")
			c["hipaa"] = append(c["hipaa"], "164.312(c)(1)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")
			c["soc_2"] = append(c["soc_2"], "CC6.8")

		// === NEW: Private Keys ===
		case "T1552", "T1552.004", "T1552.007":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "IA-5", "AC-3")

		// === NEW: Exfiltration Over Unencrypted ===
		case "T1048.003":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.1", "4.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(e)(1)", "164.312(e)(2)(ii)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-8", "AU-12")

		// === NEW: T1090 ===
		case "T1090", "T1090.001":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "4.1", "1.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "SC-13")
			c["soc_2"] = append(c["soc_2"], "CC6.6")

		// === NEW: Multi Factor Auth ===
		case "T1550", "T1550.002":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "8.3.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(d)")
			c["gdpr"] = append(c["gdpr"], "Art.32")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "IA-5")

		// === NEW: File Permissions Modification ===
		case "T1222", "T1222.002":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.4.1", "2.2.4")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "CM-7(5)", "AC-3")

		// === NEW: Credentials from Web Browsers ===
		// === NEW: Data from Local System ===
		case "T1005":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "2.2.5", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "AU-12")

		// === NEW: Data Account Control ===
		case "T1134":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "6.2", "8.2.1")
			c["hipaa"] = append(c["hipaa"], "164.312(a)(1)", "164.312(a)(2)(iv)")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "IA-5")

		// === NEW: Security Software Discovery ===
		case "T1518", "T1518.001":
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "AU-12")

		// === NEW: Data from Network Shared Drive ===
		case "T1039":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "2.2.5", "8.2.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AC-3", "SC-7")

		// === NEW: DNS Cache Poisoning ===
		case "T1595":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "SI-2(2)")

		// === NEW: Remote System Discovery ===
		case "T1018":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "1.2.5")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SC-7", "AU-12")

		// === NEW: Software Packing ===
		case "T1045":
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")

		// === NEW: Indicator Blocking ===
		case "T1054":
			c["pci_dss_v4.0"] = append(c["pci_dss_v4.0"], "5.1", "6.4.1")
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "SI-16", "CM-7(5)")

		// === NEW: Query Registry ===
		case "T1012":
			c["nist_sp_800-53"] = append(c["nist_sp_800-53"], "AU-12")
			c["soc_2"] = append(c["soc_2"], "CC7.1")
		}
	}

	// Severity-based fallback for rules without MITRE mapping
	if len(c) == 0 {
		switch {
		case severity >= 10:
			c["pci_dss_v4.0"] = []string{"6.2"}
			c["hipaa"] = []string{"164.312(a)(1)"}
			c["gdpr"] = []string{"Art.32"}
		case severity >= 7:
			c["pci_dss_v4.0"] = []string{"6.2"}
			c["hipaa"] = []string{"164.308(a)(1)(i)"}
		case severity >= 4:
			c["pci_dss_v3.2.1"] = []string{"6.2"}
			c["nist_sp_800-53"] = []string{"AU-12"}
		}
	}

	return c
}

func builtinRules() []CompiledRule {
	return []CompiledRule{
		{RuleID: "MULTIPLE_FAILED_LOGINS", Description: "Multiple failed login attempts from same source",
			Severity: 4, MITRE: "T1110.003", condition: "tag:auth_failure", threshold: 5, windowDur: 60 * time.Second,
			Actions: []RuleAction{{Playbook: "ip-reputation", Params: map[string]any{"ip": "${source_ip}"}}}},
		{RuleID: "FAILED_LOGIN_BRUTE", Description: "Single source brute-forcing login",
			Severity: 5, MITRE: "T1110", condition: "tag:auth_failure", threshold: 20, windowDur: 60 * time.Second},
		{RuleID: "HTTP_5XX_ERROR", Description: "Server error response",
			Severity: 3, condition: "tag:http_error", threshold: 1},
		{RuleID: "HTTP_4XX_BURST", Description: "Multiple client errors from same source",
			Severity: 2, condition: "tag:http_client_error", threshold: 10, windowDur: 60 * time.Second,
			Actions: []RuleAction{{Playbook: "ip-reputation", Params: map[string]any{"ip": "${client_ip}"}}}},
		{RuleID: "SUSPICIOUS_PROCESS", Description: "Suspicious process execution detected",
			Severity: 4, MITRE: "T1059", condition: "tag:process",
			Actions: []RuleAction{{Playbook: "file-analysis", Params: map[string]any{"path": "${process_path}"}}}},
		{RuleID: "HIGH_SEVERITY_ERROR", Description: "High severity error in system logs",
			Severity: 3, condition: "tag:error", threshold: 1},
		{RuleID: "WINDOWS_EVENT_4625_BURST", Description: "Multiple Windows failed logon events",
			Severity: 4, MITRE: "T1110.003", condition: "tag:auth_failure", threshold: 5, windowDur: 60 * time.Second},
		{RuleID: "BRUTE_FORCE_FALLBACK", Description: "Multiple auth failures from same source (any service)",
			Severity: 3, MITRE: "T1110", condition: "field:message ~= (?i)failed", threshold: 10, windowDur: 120 * time.Second},
		{RuleID: "WIN_POWERSHELL_4104", Description: "PowerShell script block logging (Event 4104)",
			Severity: 3, MITRE: "T1059.001", condition: "tag:powershell", threshold: 1,
			Actions: []RuleAction{{Playbook: "log-analysis", Params: map[string]any{"event_id": "4104"}}}},
		{RuleID: "WIN_SCHEDULED_TASK_4698", Description: "Scheduled task created (Event 4698) — potential persistence",
			Severity: 4, MITRE: "T1053.005", condition: "tag:persistence", threshold: 1,
			Actions: []RuleAction{{Playbook: "file-analysis", Params: map[string]any{"path": "${process_path}"}}}},
		{RuleID: "WIN_SERVICE_INSTALL_7045", Description: "New service installed (Event 7045)",
			Severity: 4, MITRE: "T1543.003", condition: "tag:service_install", threshold: 1},
		{RuleID: "WIN_DEFENDER_1116", Description: "Windows Defender detected malware (Event 1116)",
			Severity: 5, MITRE: "T1204", condition: "tag:malware_detection", threshold: 1,
			Actions: []RuleAction{{Playbook: "file-analysis", Params: map[string]any{"path": "${file_path}"}}}},
		{RuleID: "WIN_PROCESS_4688_CREATION", Description: "Process creation with command line (Event 4688)",
			Severity: 2, MITRE: "T1059", condition: "tag:process_creation", threshold: 1},
		{RuleID: "WIN_REGISTRY_PERSISTENCE", Description: "Registry persistence modification (Event 4657)",
			Severity: 3, MITRE: "T1547.001", condition: "tag:registry_change", threshold: 1},
		{RuleID: "WIN_RDP_LOGIN_4625", Description: "RDP failed login (Event 4625, LogonType 10)",
			Severity: 3, MITRE: "T1021.001", condition: "field:logontype == 10", threshold: 1},
		{RuleID: "WIN_ACCOUNT_LOCKOUT_4740", Description: "User account locked out (Event 4740)",
			Severity: 3, MITRE: "T1110", condition: "tag:account_lockout", threshold: 1},
	}
}

func (re *RuleEngine) LoadRule(r CompiledRule) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.rules = append(re.rules, r)
}

func (re *RuleEngine) Evaluate(event *Event) []*Alert {
	re.mu.RLock()
	rules := make([]CompiledRule, len(re.rules))
	copy(rules, re.rules)
	re.mu.RUnlock()

	var alerts []*Alert
	now := time.Now()

	for _, rule := range rules {
		if !re.matchesCondition(rule, event) {
			continue
		}

		suppressKey := rule.RuleID
		if rule.suppress > 0 {
			re.suppressionMu.Lock()
			if last, ok := re.suppression[suppressKey]; ok && now.Sub(last) < rule.suppress {
				re.suppressionMu.Unlock()
				continue
			}
			re.suppression[suppressKey] = now
			re.suppressionMu.Unlock()
		}

		if rule.windowDur > 0 && rule.threshold > 1 {
			corrKey := rule.RuleID + ":" + correlationKey(event, rule)
			re.correlationMu.Lock()
			re.correlation[corrKey] = append(re.correlation[corrKey], now)
			events := re.correlation[corrKey]

			var active []time.Time
			windowStart := now.Add(-rule.windowDur)
			for _, t := range events {
				if t.After(windowStart) {
					active = append(active, t)
				}
			}
			re.correlation[corrKey] = active
			re.correlationMu.Unlock()

			if len(active) < rule.threshold {
				continue
			}
		}

		alert := &Alert{
			ID:          fmt.Sprintf("%s-%d", rule.RuleID, now.UnixNano()),
			Title:       rule.Description,
			Severity:    rule.Severity,
			MITRE:       rule.MITRE,
			Source:      "siem",
			Event:       event,
			RuleID:      rule.RuleID,
			Actions:     rule.Actions,
			CreatedAt:   now,
		}
		alerts = append(alerts, alert)
	}

	return alerts
}

func (re *RuleEngine) matchesCondition(rule CompiledRule, event *Event) bool {
	if rule.condition == "" {
		return false
	}

	cond := rule.condition

	if strings.HasPrefix(cond, "tag:") {
		tag := strings.TrimPrefix(cond, "tag:")
		for _, t := range event.Tags {
			if t == tag || strings.Contains(t, tag) {
				return true
			}
		}
		return false
	}

	if strings.HasPrefix(cond, "field:") {
		fieldExpr := strings.TrimPrefix(cond, "field:")
		return evaluateFieldExpr(fieldExpr, event)
	}

	if strings.HasPrefix(cond, "severity>=") {
		minSev, _ := strconv.Atoi(cond[len("severity>="):])
		return event.Severity >= minSev
	}

	return false
}

func evaluateFieldExpr(expr string, event *Event) bool {
	parts := strings.SplitN(expr, " ", 3)
	if len(parts) < 3 {
		return false
	}

	field := parts[0]
	operator := parts[1]
	val := parts[2]

	fieldVal := getField(event.Fields, field)

	switch operator {
	case "==":
		return fmt.Sprintf("%v", fieldVal) == val
	case "!=":
		return fmt.Sprintf("%v", fieldVal) != val
	case "~=":
		pattern := strings.Trim(val, "\"")
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", fieldVal))
	case ">":
		fv, _ := strconv.ParseFloat(fmt.Sprintf("%v", fieldVal), 64)
		tv, _ := strconv.ParseFloat(val, 64)
		return fv > tv
	case "<":
		fv, _ := strconv.ParseFloat(fmt.Sprintf("%v", fieldVal), 64)
		tv, _ := strconv.ParseFloat(val, 64)
		return fv < tv
	case "in":
		return cidrMatch(fmt.Sprintf("%v", fieldVal), val)
	}

	return false
}

func getField(fields map[string]any, path string) any {
	parts := strings.Split(path, ".")
	current := fields
	for i, part := range parts {
		val, ok := current[part]
		if !ok {
			return nil
		}
		if i == len(parts)-1 {
			return val
		}
		if m, ok := val.(map[string]any); ok {
			current = m
		} else {
			return nil
		}
	}
	return nil
}

func correlationKey(event *Event, rule CompiledRule) string {
	switch rule.RuleID {
	case "MULTIPLE_FAILED_LOGINS", "HTTP_4XX_BURST":
		if ip, ok := event.Fields["client_ip"].(string); ok {
			return ip
		}
		return fmt.Sprintf("%v", event.Fields["hostname"])
	default:
		return ""
	}
}

func cidrMatch(ip, cidr string) bool {
	return strings.HasPrefix(ip, strings.Split(cidr, "/")[0])
}

func InterpolateParams(params map[string]any, event *Event) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		str, ok := v.(string)
		if !ok {
			out[k] = v
			continue
		}
		for fk, fv := range event.Fields {
			placeholder := "${" + fk + "}"
			str = strings.ReplaceAll(str, placeholder, fmt.Sprintf("%v", fv))
		}
		out[k] = str
	}
	return out
}
