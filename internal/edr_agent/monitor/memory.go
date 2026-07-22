package monitor

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type MemRegion struct {
	Start uint64
	End   uint64
	Perms string
	Path  string
}

type MemoryScanner struct {
	yara *YaraMatcher
}

func NewMemoryScanner() *MemoryScanner {
	return &MemoryScanner{yara: NewYaraMatcher()}
}

func (ms *MemoryScanner) ScanProcess(pid int) ([]*MemoryFinding, error) {
	switch runtime.GOOS {
	case "linux":
		return ms.scanLinux(pid)
	case "windows":
		return ms.scanWindows(pid)
	default:
		return nil, fmt.Errorf("memory scanning not supported on %s", runtime.GOOS)
	}
}

type MemoryFinding struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Region  string `json:"region"`
	Size    uint64 `json:"size"`
	Rule    string `json:"rule"`
	Details string `json:"details"`
}

func (ms *MemoryScanner) scanLinux(pid int) ([]*MemoryFinding, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	memPath := fmt.Sprintf("/proc/%d/mem", pid)

	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("read maps: %w", err)
	}

	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("open mem: %w", err)
	}
	defer memFile.Close()

	regions := parseProcMaps(string(data))
	var findings []*MemoryFinding

	for _, region := range regions {
		if !strings.Contains(region.Perms, "r") {
			continue
		}
		if strings.Contains(region.Perms, "s") {
			continue
		}
		if region.End-region.Start > 10*1024*1024 {
			continue
		}

		buf := make([]byte, region.End-region.Start)
		_, err := memFile.ReadAt(buf, int64(region.Start))
		if err != nil {
			continue
		}

		matches := ms.yara.MatchBytes(buf)
		for _, match := range matches {
			findings = append(findings, &MemoryFinding{
				PID:     pid,
				Region:  fmt.Sprintf("0x%x-0x%x", region.Start, region.End),
				Size:    region.End - region.Start,
				Rule:    match.Name,
				Details: match.Description,
			})
		}
	}

	return findings, nil
}

func (ms *MemoryScanner) scanWindows(pid int) ([]*MemoryFinding, error) {
	return nil, fmt.Errorf("Windows memory scanning requires native API")
}

func parseProcMaps(data string) []MemRegion {
	var regions []MemRegion
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addrParts := strings.SplitN(fields[0], "-", 2)
		if len(addrParts) != 2 {
			continue
		}
		start, _ := strconv.ParseUint(addrParts[0], 16, 64)
		end, _ := strconv.ParseUint(addrParts[1], 16, 64)
		regions = append(regions, MemRegion{
			Start: start, End: end, Perms: fields[1], Path: strings.Join(fields[4:], " "),
		})
	}
	return regions
}
