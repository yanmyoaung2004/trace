package monitor

import (
	"encoding/binary"
	"log"
)

const maxPESize = 100 * 1024 * 1024

type PEMemory struct {
	IsPE          bool
	Sections      []PESection
	EntryPoint    uint32
	ImageBase     uint32
	Subsystem     uint16
	IsPacked      bool
	PackerName    string
	PackerConf    float64
	NumImports    int
	HasTLS        bool
	HasRelocs     bool
	SuspiciousSections int
}

type PESection struct {
	Name        string
	VirtualAddr uint32
	VirtualSize uint32
	RawSize     uint32
	RawOffset   uint32
	Entropy     float64
	Characteristics uint32
}

func AnalyzePE(data []byte) *PEMemory {
	r := &PEMemory{}
	if len(data) < 64 || len(data) > maxPESize {
		return r
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return r
	}

	peOff := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOff < 64 || peOff+64 > len(data) {
		return r
	}
	if data[peOff] != 'P' || data[peOff+1] != 'E' {
		return r
	}

	r.IsPE = true
	pe := peOff

	// Validate PE header bounds
	if pe+248 > len(data) {
		return r
	}

	r.EntryPoint = binary.LittleEndian.Uint32(data[pe+16 : pe+20])
	r.Subsystem = binary.LittleEndian.Uint16(data[pe+68 : pe+70])
	r.ImageBase = binary.LittleEndian.Uint32(data[pe+52 : pe+56])

	numSections := int(binary.LittleEndian.Uint16(data[pe+2 : pe+4]))
	numSections = clamp(numSections, 0, 40)

	// Import directory
	importRVA := binary.LittleEndian.Uint32(data[pe+104 : pe+108])
	importSize := binary.LittleEndian.Uint32(data[pe+112 : pe+116])
	if importSize > 0 && importRVA > 0 {
		r.NumImports = countPEImports(data)
	}

	// TLS directory
	tlsRVA := binary.LittleEndian.Uint32(data[pe+136 : pe+140])
	r.HasTLS = tlsRVA > 0 && binary.LittleEndian.Uint32(data[pe+140:pe+144]) > 0

	// Relocations
	relocRVA := binary.LittleEndian.Uint32(data[pe+160 : pe+164])
	r.HasRelocs = relocRVA > 0 && binary.LittleEndian.Uint32(data[pe+164:pe+168]) > 0

	secStart := pe + 24 + 208
	for i := 0; i < numSections; i++ {
		off := secStart + i*40
		if off+40 > len(data) {
			break
		}

		sec := PESection{
			Name:             trimNull(string(data[off : off+8])),
			VirtualAddr:      binary.LittleEndian.Uint32(data[off+12 : off+16]),
			VirtualSize:      binary.LittleEndian.Uint32(data[off+8 : off+12]),
			RawSize:          binary.LittleEndian.Uint32(data[off+16 : off+20]),
			RawOffset:        binary.LittleEndian.Uint32(data[off+20 : off+24]),
			Characteristics:  binary.LittleEndian.Uint32(data[off+36 : off+40]),
		}

		if sec.RawSize > 0 && int(sec.RawOffset+sec.RawSize) <= len(data) && sec.RawSize <= maxPESize {
			sec.Entropy = calculateEntropy(data[sec.RawOffset : sec.RawOffset+sec.RawSize])
		}

		r.Sections = append(r.Sections, sec)
	}

	r.detectPacker()
	return r
}

func detectPacker(pe *PEMemory) bool {
	if !pe.IsPE || len(pe.Sections) == 0 {
		return false
	}
	return pe.IsPacked
}

func (pe *PEMemory) detectPacker() {
	score := 0.0

	if len(pe.Sections) == 0 {
		return
	}

	for _, s := range pe.Sections {
		switch s.Name {
		case "UPX0", "UPX1", "UPX2":
			pe.PackerName = "UPX"; score = 0.95
		case ".packed":
			pe.PackerName = "Generic Packer"; score = 0.8
		case ".MPRSS":
			pe.PackerName = "MPRESS"; score = 0.95
		case ".SHELL":
			pe.PackerName = "ShellCrypt"; score = 0.9
		case ".mackt":
			pe.PackerName = "Themida"; score = 0.95
		case ".text!":
			pe.PackerName = "Enigma Protector"; score = 0.9
		case "PACKER":
			pe.PackerName = "PACKER"; score = 0.9
		}
		if pe.PackerName != "" {
			pe.IsPacked = true; pe.PackerConf = score
			return
		}
	}

	// Check 2: Section name length anomaly
	for _, s := range pe.Sections {
		if s.Name != "" && len(s.Name) > 8 {
			score += 0.25
			pe.SuspiciousSections++
		}
	}

	// Check 3: Single high-entropy section (packed binary)
	highEntropySections := 0
	for _, s := range pe.Sections {
		if s.Entropy > 7.0 && s.RawSize > 2048 {
			highEntropySections++
		}
	}
	score += float64(highEntropySections) * 0.2

	// Check 4: Entry point in last section (packer characteristic)
	if len(pe.Sections) > 1 {
		last := pe.Sections[len(pe.Sections)-1]
		epRange := pe.EntryPoint >= last.VirtualAddr &&
			pe.EntryPoint < last.VirtualAddr+last.VirtualSize
		if epRange && last.Entropy > 6.5 {
			score += 0.3
		}
		if epRange && last.Entropy > 7.5 {
			score += 0.2
		}
	}

	// Check 5: Very few imports for a normal PE
	if pe.NumImports < 5 && len(pe.Sections) > 2 {
		score += 0.3
	}

	// Check 6: TLS callbacks present (common in packers)
	if pe.HasTLS && pe.NumImports < 10 {
		score += 0.2
	}

	// Check 7: High entropy in first section (code section should be 4-6)
	if len(pe.Sections) > 0 && pe.Sections[0].Entropy > 7.0 {
		score += 0.2
	}

	if score >= 0.6 {
		pe.IsPacked = true
		pe.PackerConf = score
		if pe.PackerName == "" && highEntropySections > 1 {
			pe.PackerName = "VMProtect/Confuser"
		} else if pe.PackerName == "" {
			pe.PackerName = "Unknown Packer"
		}
	}
}

func countPEImports(data []byte) int {
	// Simple import count by looking for DLL name references
	// Real implementation would walk the import directory table
	count := 0
	markers := [][]byte{
		{'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'd', 'l', 'l'},
		{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'},
		{'U', 'S', 'E', 'R', '3', '2', '.', 'd', 'l', 'l'},
		{'A', 'D', 'V', 'A', 'P', 'I', '3', '2', '.', 'd', 'l', 'l'},
		{'W', 'S', '2', '_', '3', '2', '.', 'd', 'l', 'l'},
		{'w', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l'},
		{'w', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l'},
	}
	for _, m := range markers {
		if containsBytes(data, m) {
			count++
		}
	}
	return count
}

func containsBytes(data, sub []byte) bool {
	if len(sub) > len(data) {
		return false
	}
	for i := 0; i <= len(data)-len(sub); i++ {
		match := true
		for j := range sub {
			if data[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func trimNull(s string) string {
	for i, c := range s {
		if c == 0 {
			return s[:i]
		}
	}
	return s
}

func clamp(n, min, max int) int {
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

var _ = log.Printf
