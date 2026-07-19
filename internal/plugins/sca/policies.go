package sca

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type policyEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Data string `json:"data"`
}

var loadedPolicies []policyEntry

func init() {
	json.Unmarshal([]byte(policiesJSON), &loadedPolicies)
}

func ListPolicies() []policyEntry {
	return loadedPolicies
}

func GetPolicy(id string) *policyEntry {
	for _, p := range loadedPolicies {
		if p.ID == id || strings.HasSuffix(p.Name, id) {
			return &p
		}
	}
	return nil
}

func DetectOSPolicy() *policyEntry {
	osName := runtime.GOOS

	switch osName {
	case "linux":
		return detectLinuxPolicy()
	case "windows":
		return GetPolicy("cis_win")
	case "darwin":
		return GetPolicy("cis_apple_macOS")
	}
	return nil
}

func detectLinuxPolicy() *policyEntry {
	distro := readOSRelease()
	if distro == "" {
		distro = readRedHatRelease()
	}

	for _, p := range loadedPolicies {
		if strings.Contains(p.Name, distro) {
			return &p
		}
	}

	for _, p := range loadedPolicies {
		if strings.Contains(p.Name, "linux") && !strings.Contains(p.Name, "apple") {
			return &p
		}
	}
	return nil
}

func readOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "ID=") {
			id := strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
			id = strings.TrimSpace(id)

			version, _ := os.ReadFile("/etc/debian_version")
			if version != nil {
				verStr := string(version)
				switch {
				case strings.HasPrefix(verStr, "12"):
					return "debian12"
				case strings.HasPrefix(verStr, "11"):
					return "debian11"
				case strings.HasPrefix(verStr, "10"):
					return "debian10"
				case strings.HasPrefix(verStr, "9"):
					return "debian9"
				case strings.HasPrefix(verStr, "8"):
					return "debian8"
				}
			}

			switch id {
			case "ubuntu":
				return readUbuntuVersion()
			case "rhel", "centos":
				return readRHELVersion()
			case "amzn":
				return "amazon_linux"
			case "almalinux":
				return "alma_linux"
			case "rocky":
				return "rocky_linux"
			case "debian":
				return "debian12"
			case "sles", "suse":
				return "sles"
			case "ol", "oracle":
				return "oracle_linux"
			}
			return id
		}
	}
	return ""
}

func readRedHatRelease() string {
	data, err := os.ReadFile("/etc/redhat-release")
	if err != nil {
		return ""
	}
	content := string(data)
	content = strings.ToLower(content)
	switch {
	case strings.Contains(content, "almalinux"):
		return "alma_linux"
	case strings.Contains(content, "rocky"):
		return "rocky_linux"
	case strings.Contains(content, "centos"):
		return "centos"
	case strings.Contains(content, "red hat"):
		return "rhel"
	}
	return ""
}

func readUbuntuVersion() string {
	data, err := os.ReadFile("/etc/lsb-release")
	if err != nil {
		return "ubuntu22-04"
	}
	content := string(data)
	switch {
	case strings.Contains(content, "24.04"):
		return "ubuntu24-04"
	case strings.Contains(content, "22.04"):
		return "ubuntu22-04"
	case strings.Contains(content, "20.04"):
		return "ubuntu20-04"
	case strings.Contains(content, "18.04"):
		return "ubuntu18-04"
	}
	return "ubuntu22-04"
}

func readRHELVersion() string {
	data, err := os.ReadFile("/etc/redhat-release")
	if err != nil {
		return "rhel9"
	}
	content := string(data)
	switch {
	case strings.Contains(content, "release 9"):
		return "rhel9"
	case strings.Contains(content, "release 8"):
		return "rhel8"
	case strings.Contains(content, "release 7"):
		return "rhel7"
	}
	return "rhel9"
}

func init() {
	_ = filepath.Join
}
