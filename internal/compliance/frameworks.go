package compliance

import (
	"fmt"
	"sort"
	"strings"
)

type Framework struct {
	ID          string
	Name        string
	Description string
	Controls    []Control
}

type Control struct {
	ID          string
	Title       string
	Description string
	Category    string
}

var Frameworks = map[string]*Framework{}

func init() {
	Frameworks["pci_dss_v4.0"] = &Framework{
		ID: "pci_dss_v4.0", Name: "PCI DSS v4.0",
		Description: "Payment Card Industry Data Security Standard v4.0 — 12 requirements for securing cardholder data",
		Controls: []Control{
			{"1.2.5", "Network access controls", "Restrict network access to cardholder data", "Network Security"},
			{"1.4", "Network segmentation", "Segment cardholder data environment from untrusted networks", "Network Security"},
			{"2.2.2", "Configuration standards", "Establish secure configuration standards", "Configuration"},
			{"2.2.4", "Vendor default accounts", "Change vendor defaults and remove unnecessary services", "Configuration"},
			{"2.2.5", "Unnecessary services", "Remove or disable unnecessary services and protocols", "Configuration"},
			{"2.2.7", "Insecure protocols", "Disable insecure protocols and ciphers", "Configuration"},
			{"4.1", "Encryption in transit", "Use strong cryptography for cardholder data in transit", "Encryption"},
			{"4.1.1", "Encryption protocols", "Use strong encryption protocols like TLS 1.2+", "Encryption"},
			{"4.2.1", "Email encryption", "Encrypt cardholder data sent via email", "Encryption"},
			{"4.2.2", "Encryption strength", "Use strong cryptography (AES-256, RSA-2048+)", "Encryption"},
			{"6.2", "Patch management", "Apply security patches within 30 days of release", "Patch Management"},
			{"6.4.1", "Change control", "Implement change control procedures for all production changes", "Change Management"},
			{"8.2.1", "Authentication", "Implement strong authentication for all user access", "Access Control"},
			{"8.3.2", "Multi-factor authentication", "MFA for all non-console admin access to CDE", "Access Control"},
		},
	}

	Frameworks["pci_dss_v3.2.1"] = &Framework{
		ID: "pci_dss_v3.2.1", Name: "PCI DSS v3.2.1",
		Description: "Payment Card Industry Data Security Standard v3.2.1",
		Controls: []Control{
			{"1.1.6", "Firewall policies", "Review firewall rulesets every 6 months", "Network Security"},
			{"1.2.1", "DMZ", "Place all wireless networks in DMZ", "Network Security"},
			{"2.1.1", "Vendor defaults", "Change all vendor passwords", "Configuration"},
			{"2.2.2", "Configuration standards", "Develop configuration standards for all system components", "Configuration"},
			{"2.2.5", "Inventory", "Maintain inventory of business-critical assets", "Configuration"},
			{"4.1", "Encryption in transit", "Encrypt cardholder data over open networks", "Encryption"},
			{"4.1.1", "Wireless encryption", "Use strong wireless encryption (WPA2/TKIP)", "Encryption"},
			{"6.2", "Patch management", "Critical patches applied within 30 days", "Patch Management"},
			{"8.2.1", "Authentication", "Unique IDs for all users", "Access Control"},
		},
	}

	Frameworks["hipaa"] = &Framework{
		ID: "hipaa", Name: "HIPAA Security Rule",
		Description: "Health Insurance Portability and Accountability Act — Security Rule for protecting ePHI",
		Controls: []Control{
			{"164.308(a)(1)(i)", "Security management", "Implement security management process", "Administrative"},
			{"164.308(a)(4)(i)", "Access authorization", "Implement policies for granting access to ePHI", "Administrative"},
			{"164.308(a)(5)(i)", "Security awareness", "Security awareness training for all workforce members", "Administrative"},
			{"164.312(a)(1)", "Access control", "Implement technical policies for ePHI access", "Technical"},
			{"164.312(a)(2)(iv)", "Unique user identification", "Assign unique user IDs for tracking access", "Technical"},
			{"164.312(c)(1)", "Integrity controls", "Implement controls to protect ePHI integrity", "Technical"},
			{"164.312(c)(2)", "Mechanism to authenticate ePHI", "Implement mechanism to corroborate ePHI integrity", "Technical"},
			{"164.312(d)", "Person authentication", "Implement procedures to verify person identity", "Technical"},
			{"164.312(e)(1)", "Transmission security", "Implement security measures for ePHI transmission", "Technical"},
			{"164.312(e)(2)(i)", "Integrity controls", "Ensure ePHI integrity during transmission", "Technical"},
			{"164.312(e)(2)(ii)", "Encryption in transit", "Encrypt ePHI when transmitted over networks", "Technical"},
			{"164.310(a)(1)", "Facility access", "Limit facility access to authorized individuals", "Physical"},
			{"164.310(d)(1)", "Device controls", "Implement policies for hardware and device security", "Physical"},
		},
	}

	Frameworks["gdpr"] = &Framework{
		ID: "gdpr", Name: "GDPR",
		Description: "EU General Data Protection Regulation — 7 principles + data subject rights",
		Controls: []Control{
			{"Art.5", "Data processing principles", "Lawfulness, fairness, transparency in data processing", "Principles"},
			{"Art.6", "Lawful processing", "Processing must have a lawful basis (consent, contract, etc.)", "Principles"},
			{"Art.7", "Consent", "Consent must be freely given, specific, informed and unambiguous", "Consent"},
			{"Art.15", "Right of access", "Data subjects have right to access their personal data", "Data Subject Rights"},
			{"Art.16", "Right to rectification", "Data subjects can request inaccurate data correction", "Data Subject Rights"},
			{"Art.17", "Right to erasure", "Right to be forgotten — delete data when no longer needed", "Data Subject Rights"},
			{"Art.18", "Restriction of processing", "Data subjects can restrict processing in certain cases", "Data Subject Rights"},
			{"Art.20", "Data portability", "Data subjects can receive and transfer their data", "Data Subject Rights"},
			{"Art.25", "Data protection by design", "Implement data protection from system design stage", "Accountability"},
			{"Art.30", "Records of processing", "Maintain records of all data processing activities", "Accountability"},
			{"Art.32", "Security of processing", "Implement appropriate technical and organizational measures", "Security"},
			{"Art.33", "Breach notification", "Notify DPA within 72 hours of data breach", "Breach Response"},
			{"Art.35", "DPIA", "Conduct Data Protection Impact Assessments for high-risk processing", "Accountability"},
		},
	}

	Frameworks["nist_sp_800-53"] = &Framework{
		ID: "nist_sp_800-53", Name: "NIST SP 800-53 Rev.5",
		Description: "NIST Security and Privacy Controls for Information Systems",
		Controls: []Control{
			{"AC-17(2)", "Remote access protection", "Protect remote access sessions with encryption", "Access Control"},
			{"AC-3", "Access enforcement", "Enforce approved authorizations for logical access", "Access Control"},
			{"AU-3", "Audit record content", "Ensure audit records contain sufficient information", "Audit"},
			{"AU-12", "Audit generation", "Provide audit record generation capability", "Audit"},
			{"CM-7(5)", "Least functionality", "Authorized software — allowlist approved applications", "Configuration"},
			{"IA-5", "Authenticator management", "Manage system authenticators throughout lifecycle", "Identity"},
			{"SC-7", "Boundary protection", "Monitor and control communications at system boundary", "System"},
			{"SC-8", "Transmission confidentiality", "Protect transmitted data from unauthorized disclosure", "System"},
			{"SC-8(1)", "Cryptographic protection", "Use cryptography to protect transmitted data", "System"},
			{"SC-13", "Cryptographic protection", "Use validated cryptography for security functions", "System"},
			{"SI-2(2)", "Flaw remediation", "Automate patch management and flaw remediation", "System Integrity"},
			{"SI-16", "Memory protection", "Implement memory protection (ASLR, DEP, NX)", "System Integrity"},
		},
	}

	Frameworks["iso_27001-2013"] = &Framework{
		ID: "iso_27001-2013", Name: "ISO 27001:2013",
		Description: "Information Security Management Standard — Annex A controls",
		Controls: []Control{
			{"A.8.1.1", "Asset inventory", "Maintain inventory of information assets", "Asset Management"},
			{"A.8.1.3", "Asset acceptance", "Establish rules for acceptable use of assets", "Asset Management"},
			{"A.10.1.1", "Cryptographic policy", "Develop and implement cryptographic controls policy", "Cryptography"},
			{"A.12.4.1", "Event logging", "Produce and review event logs regularly", "Operations"},
			{"A.12.5.1", "Change management", "Implement change management procedures", "Operations"},
			{"A.12.6.2", "Patch management", "Manage installation of security patches", "Operations"},
			{"A.12.14.1", "Logging", "Ensure event logging is enabled for information systems", "Operations"},
			{"A.13.1.1", "Network controls", "Manage and control networks to protect information", "Network"},
			{"A.13.1.3", "Network segregation", "Segregate networks to isolate critical services", "Network"},
		},
	}

	Frameworks["soc_2"] = &Framework{
		ID: "soc_2", Name: "SOC 2",
		Description: "Service Organization Control 2 — Trust Services Criteria",
		Controls: []Control{
			{"CC5.2", "Control activities", "Select and develop control activities to mitigate risks", "Control Activities"},
			{"CC6.3", "Access provisioning", "Approve, administer, and manage user access", "Access Control"},
			{"CC6.6", "Logical access", "Implement logical access security measures", "Access Control"},
			{"CC6.8", "System changes", "Manage system changes to maintain integrity", "Change Management"},
			{"CC7.1", "Monitoring activities", "Monitor system operations and detect anomalies", "Monitoring"},
		},
	}

	Frameworks["cis_csc_v8"] = &Framework{
		ID: "cis_csc_v8", Name: "CIS Critical Security Controls v8",
		Description: "Center for Internet Security Critical Security Controls",
		Controls: []Control{
			{"2.5", "Software inventory", "Maintain inventory of authorized software", "Inventory"},
			{"3.10", "Data encryption", "Encrypt sensitive data at rest and in transit", "Encryption"},
			{"4.8", "Unnecessary services", "Disable unnecessary services and ports", "Hardening"},
			{"7.3", "Patch management", "Manage timely patching of systems", "Patch"},
			{"8.8", "Logging", "Maintain audit logs of system activity", "Logging"},
			{"10.5", "Anti-malware", "Deploy and maintain anti-malware software", "Defenses"},
		},
	}
}

type ComplianceCheckResult struct {
	CheckID     int
	Title       string
	Status      string
	Remediation string
	Compliance  map[string][]string
}

func (f *Framework) CoverageSummary(checkResults []ComplianceCheckResult) string {
	mapped := 0
	for _, cr := range checkResults {
		if _, ok := cr.Compliance[f.ID]; ok {
			mapped++
		}
	}
	rate := 0.0
	if len(checkResults) > 0 {
		rate = float64(mapped) / float64(len(checkResults)) * 100
	}
	return fmt.Sprintf("%s: %d/%d checks mapped (%.0f%%)", f.Name, mapped, len(checkResults), rate)
}

func (f *Framework) CategoryBreakdown(checkResults []ComplianceCheckResult) map[string]struct{ Passed, Failed, Total int } {
	breakdown := make(map[string]struct{ Passed, Failed, Total int })
	for _, c := range f.Controls {
		cat := c.Category
		b := breakdown[cat]
		b.Total++
		breakdown[cat] = b
		for _, ch := range checkResults {
			if ids, ok := ch.Compliance[f.ID]; ok {
				for _, id := range ids {
					if id == c.ID {
						b := breakdown[cat]
						if ch.Status == "pass" {
							b.Passed++
						} else {
							b.Failed++
						}
						breakdown[cat] = b
					}
				}
			}
		}
	}
	return breakdown
}

func (f *Framework) ReportByControl(checkResults []ComplianceCheckResult) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# %s Compliance Report\n\n", f.Name))
	b.WriteString(fmt.Sprintf("%s\n\n", f.Description))
	b.WriteString(fmt.Sprintf("Total controls: %d\n\n", len(f.Controls)))

	total := len(f.Controls)
	passed, failed, notMapped := 0, 0, 0

	type controlStatus struct {
		Control Control
		Passed  int
		Failed  int
		Total   int
		Mapped  bool
	}

	var results []controlStatus
	for _, c := range f.Controls {
		cs := controlStatus{Control: c, Mapped: false}
		for _, ch := range checkResults {
			if ids, ok := ch.Compliance[f.ID]; ok {
				for _, id := range ids {
					if id == c.ID {
						cs.Mapped = true
						cs.Total++
						if ch.Status == "pass" {
							cs.Passed++
						} else {
							cs.Failed++
						}
					}
				}
			}
		}
		results = append(results, cs)
		if cs.Mapped {
			if cs.Failed == 0 {
				passed++
			} else {
				failed++
			}
		} else {
			notMapped++
		}
	}

	score := 0.0
	if total > 0 {
		score = float64(passed) / float64(total) * 100
	}
	b.WriteString(fmt.Sprintf("Compliance score: %.0f%% (%d/%d controls passed)\n\n", score, passed, total))
	b.WriteString(fmt.Sprintf("Failed: %d | Not covered: %d\n\n", failed, notMapped))

	b.WriteString("| Control | Category | Title | Status | Checks |\n")
	b.WriteString("|---------|----------|-------|--------|--------|\n")
	for _, r := range results {
		status := "❌ Not covered"
		checkInfo := "-"
		if r.Mapped {
			if r.Failed == 0 {
				status = "✅ Pass"
			} else {
				status = fmt.Sprintf("⚠️ %d/%d failed", r.Failed, r.Total)
			}
			checkInfo = fmt.Sprintf("%d/%d", r.Passed, r.Total)
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", r.Control.ID, r.Control.Category, r.Control.Title, status, checkInfo))
	}

	return b.String()
}

func (r ComplianceCheckResult) FrameworksList() string {
	var fws []string
	for f := range r.Compliance {
		fws = append(fws, f)
	}
	sort.Strings(fws)
	return strings.Join(fws, ", ")
}

func supportedFrameworks() string {
	var names []string
	for k := range Frameworks {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
