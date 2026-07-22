package monitor

import (
	"encoding/binary"
)

type PEMemory struct {
	IsPE         bool
	Sections     []PESection
	EntryPoint   uint32
	ImageBase    uint32
	Subsystem    uint16
	IsPacked     bool
	PackerName   string
}

type PESection struct {
	Name       string
	VirtualAddr uint32
	RawSize     uint32
	RawOffset   uint32
	Entropy     float64
}

func AnalyzePE(data []byte) *PEMemory {
	result := &PEMemory{}
	if len(data) < 64 {
		return result
	}

	if data[0] != 'M' || data[1] != 'Z' {
		return result
	}

	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset+4 > len(data) {
		return result
	}

	if data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		return result
	}

	result.IsPE = true
	pe := peOffset

	if pe+20 > len(data) {
		return result
	}
	result.EntryPoint = binary.LittleEndian.Uint32(data[pe+16 : pe+20])
	result.Subsystem = binary.LittleEndian.Uint16(data[pe+68 : pe+70])
	result.ImageBase = binary.LittleEndian.Uint32(data[pe+52 : pe+56])

	numSections := int(binary.LittleEndian.Uint16(data[pe+2 : pe+4]))
	sectionOffset := pe + 24 + 216

	for i := 0; i < numSections && i < 40; i++ {
		off := sectionOffset + i*40
		if off+40 > len(data) {
			break
		}

		secNameBytes := data[off : off+8]
		secName := string(secNameBytes)
		secName = trimNull(secName)

		sec := PESection{
			Name:        secName,
			VirtualAddr: binary.LittleEndian.Uint32(data[off+12 : off+16]),
			RawSize:     binary.LittleEndian.Uint32(data[off+16 : off+20]),
			RawOffset:   binary.LittleEndian.Uint32(data[off+20 : off+24]),
			Entropy:     0,
		}

		if sec.RawSize > 0 && int(sec.RawOffset+sec.RawSize) <= len(data) {
			sec.Entropy = calculateEntropy(data[sec.RawOffset : sec.RawOffset+sec.RawSize])
		}

		result.Sections = append(result.Sections, sec)
	}

	// Packer detection
	result.IsPacked = detectPacker(result)
	if result.IsPacked {
		result.PackerName = identifyPacker(result)
	}

	return result
}

func detectPacker(pe *PEMemory) bool {
	if !pe.IsPE || len(pe.Sections) == 0 {
		return false
	}

	// One section with high entropy = packed
	if len(pe.Sections) <= 2 {
		for _, s := range pe.Sections {
			if s.Entropy > 7.0 && s.RawSize > 4096 {
				return true
			}
		}
	}

	// Suspicious section names
	packedNames := map[string]bool{
		"UPX0": true, "UPX1": true, "UPX2": true,
		".packed": true, ".pdata": true, ".mackt": true,
		".MPRSS": true, ".SHELL": true, ".text!": true,
	}

	for _, s := range pe.Sections {
		if packedNames[s.Name] {
			return true
		}
		if s.Name != "" && (s.Name[0] == '.' && len(s.Name) > 8) {
			return true
		}
	}

	// Entry point in last section (typical for packers)
	if len(pe.Sections) > 2 {
		last := pe.Sections[len(pe.Sections)-1]
		if pe.EntryPoint >= last.VirtualAddr && pe.EntryPoint < last.VirtualAddr+last.RawSize {
			if last.Entropy > 6.5 {
				return true
			}
		}
	}

	return false
}

func identifyPacker(pe *PEMemory) string {
	for _, s := range pe.Sections {
		switch s.Name {
		case "UPX0", "UPX1", "UPX2":
			return "UPX"
		case ".packed":
			return "Generic Packer"
		case ".MPRSS":
			return "MPRESS"
		case ".SHELL":
			return "ShellCrypt"
		case ".mackt":
			return "Themida"
		case ".text!":
			return "Enigma Protector"
		}
	}
	return "Unknown Packer"
}

func trimNull(s string) string {
	for i, c := range s {
		if c == 0 {
			return s[:i]
		}
	}
	return s
}
