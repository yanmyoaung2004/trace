package monitor

import (
	"encoding/binary"
	"fmt"
)

const maxPESize = 100 * 1024 * 1024

const (
	peMachineI386   = 0x014c
	peMachineAMD64  = 0x8664
	peMachineARM64  = 0xaa64
	peMachineIA64   = 0x0200

	imageOrdinalFlag32 = 0x80000000
	imageOrdinalFlag64 = 0x8000000000000000

	dirEntryImport   = 1
	dirEntryIAT      = 12
	dirEntryDelayImport = 15
)

type PEResource struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Size       uint32 `json:"size"`
	Data       []byte `json:"-"`
}

type PEMemory struct {
	IsPE       bool
	Is64       bool
	Sections   []PESection
	EntryPoint uint32
	ImageBase  uint64
	Subsystem  uint16
	IsPacked   bool
	PackerName string
	PackerConf float64
	Imports    []ImportDLL
	HasTLS     bool
	HasRelocs  bool
	SuspiciousSections int
	Resources  []PEResource
}

type PESection struct {
	Name       string
	VirtualAddr uint32
	VirtualSize uint32
	RawSize     uint32
	RawOffset   uint32
	Entropy     float64
	Characteristics uint32
}

type ImportDLL struct {
	Name    string
	Imports []string
	Ordinal bool
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
	if peOff < 64 || peOff+256 > len(data) {
		return r
	}
	if data[peOff] != 'P' || data[peOff+1] != 'E' {
		return r
	}

	r.IsPE = true
	pe := peOff

	machine := binary.LittleEndian.Uint16(data[pe+4 : pe+6])
	r.Is64 = machine == peMachineAMD64 || machine == peMachineARM64 || machine == peMachineIA64

	// Optional header magic determines PE32 (0x10b) vs PE32+ (0x20b)
	optHdrMagic := binary.LittleEndian.Uint16(data[pe+20 : pe+22])
	isPE32Plus := optHdrMagic == 0x20b
	isPE32 := optHdrMagic == 0x10b
	_ = isPE32
	_ = isPE32Plus

	numSections := int(binary.LittleEndian.Uint16(data[pe+2 : pe+4]))
	numSections = clamp(numSections, 0, 40)

	// Optional header offset
	optHdrSize := int(binary.LittleEndian.Uint16(data[pe+16 : pe+18]))
	optHdrOff := pe + 20

	if optHdrOff+optHdrSize > len(data) || optHdrSize < 96 {
		return r
	}

	r.EntryPoint = binary.LittleEndian.Uint32(data[optHdrOff+16 : optHdrOff+20])
	r.Subsystem = binary.LittleEndian.Uint16(data[optHdrOff+68 : optHdrOff+70])

	if r.Is64 && optHdrOff+112 <= len(data) {
		r.ImageBase = binary.LittleEndian.Uint64(data[optHdrOff+24 : optHdrOff+32])
	} else if optHdrOff+28 <= len(data) {
		r.ImageBase = uint64(binary.LittleEndian.Uint32(data[optHdrOff+28 : optHdrOff+32]))
	}

	// Data directories start at offset 96 in optional header
	ddOff := optHdrOff + 96
	numDataDirs := int(binary.LittleEndian.Uint32(data[optHdrOff+92 : optHdrOff+96]))
	if numDataDirs > 16 {
		numDataDirs = 16
	}

	parseDir := func(idx int) (uint32, uint32) {
		if idx >= numDataDirs {
			return 0, 0
		}
		off := ddOff + idx*8
		if off+8 > len(data) {
			return 0, 0
		}
		return binary.LittleEndian.Uint32(data[off : off+4]),
			binary.LittleEndian.Uint32(data[off+4 : off+8])
	}

	importRVA, importSize := parseDir(dirEntryImport)
	if importRVA > 0 && importSize >= 20 {
		r.Imports = walkImportDescriptors(data, importRVA, r.Sections, r.Is64)
	}

	tlsRVA, tlsSize := parseDir(9)
	r.HasTLS = tlsRVA > 0 && tlsSize >= 8

	relocRVA, relocSize := parseDir(5)
	r.HasRelocs = relocRVA > 0 && relocSize > 0

	// Parse resource directory (index 2)
	resRVA, resSize := parseDir(2)
	if resRVA > 0 && resSize > 0 {
		r.Resources = parsePEResources(data, resRVA, r.Sections)
	}

	// Sections
	secStart := pe + 24 + optHdrSize
	for i := 0; i < numSections; i++ {
		off := secStart + i*40
		if off+40 > len(data) {
			break
		}
		sec := PESection{
			Name:           cstring(data[off : off+8]),
			VirtualSize:    binary.LittleEndian.Uint32(data[off+8 : off+12]),
			VirtualAddr:    binary.LittleEndian.Uint32(data[off+12 : off+16]),
			RawSize:        binary.LittleEndian.Uint32(data[off+16 : off+20]),
			RawOffset:      binary.LittleEndian.Uint32(data[off+20 : off+24]),
			Characteristics: binary.LittleEndian.Uint32(data[off+36 : off+40]),
		}
		if sec.RawSize > 0 && int(sec.RawOffset+sec.RawSize) <= len(data) && sec.RawSize <= maxPESize {
			sec.Entropy = calculateEntropy(data[sec.RawOffset : sec.RawOffset+sec.RawSize])
		}
		r.Sections = append(r.Sections, sec)
	}

	r.detectPacker()
	return r
}

func rvaToOffset(rva uint32, sections []PESection, imageBase uint64) int {
	if rva == 0 {
		return -1
	}
	for _, s := range sections {
		if s.VirtualAddr > 0 && rva >= s.VirtualAddr && rva < s.VirtualAddr+max(s.VirtualSize, s.RawSize) {
			return int(s.RawOffset + (rva - s.VirtualAddr))
		}
	}
	return int(rva)
}

func parsePEResources(data []byte, resRVA uint32, sections []PESection) []PEResource {
	var res []PEResource
	off := rvaToOffset(resRVA, sections, 0)
	if off < 0 || off+16 > len(data) {
		return nil
	}

	numNamed := int(binary.LittleEndian.Uint16(data[off+12 : off+14]))
	numID := int(binary.LittleEndian.Uint16(data[off+14 : off+16]))
	totalEntries := numNamed + numID

	entryOff := off + 16
	for i := 0; i < totalEntries && i < 20; i++ {
		if entryOff+8 > len(data) {
			break
		}
		entry := binary.LittleEndian.Uint32(data[entryOff : entryOff+4])
		_ = entry

		subOff := int(binary.LittleEndian.Uint32(data[entryOff+4:entryOff+8])) & 0x7FFFFFFF
		subOff = rvaToOffset(uint32(subOff), sections, 0) + off - rvaToOffset(resRVA, sections, 0)
		if subOff < off || subOff+16 > len(data) {
			entryOff += 8
			continue
		}

		subNamed := int(binary.LittleEndian.Uint16(data[subOff+12 : subOff+14]))
		subID := int(binary.LittleEndian.Uint16(data[subOff+14 : subOff+16]))
		subTotal := subNamed + subID

		subEntryOff := subOff + 16
		for j := 0; j < subTotal && j < 20; j++ {
			if subEntryOff+8 > len(data) {
				break
			}
			dataOff := int(binary.LittleEndian.Uint32(data[subEntryOff+4:subEntryOff+8])) & 0x7FFFFFFF
			dataOff = rvaToOffset(uint32(dataOff), sections, 0)
			if dataOff < 0 || dataOff+16 > len(data) {
				subEntryOff += 8
				continue
			}

			dataRVA := binary.LittleEndian.Uint32(data[dataOff : dataOff+4])
			dataSize := binary.LittleEndian.Uint32(data[dataOff+4 : dataOff+8])
			dataOff2 := rvaToOffset(dataRVA, sections, 0)

			r := PEResource{
				Size: dataSize,
			}

			if dataOff2 >= 0 && dataOff2+int(dataSize) <= len(data) && dataSize > 0 && dataSize < 10*1024*1024 {
				r.Data = make([]byte, dataSize)
				copy(r.Data, data[dataOff2:dataOff2+int(dataSize)])
				r.Name = detectResourceType(r.Data)
				r.Type = detectResourceCategory(i)
			}

			res = append(res, r)
			subEntryOff += 8
		}

		entryOff += 8
	}
	return res
}

func detectResourceCategory(index int) string {
	categories := map[int]string{
		0: "CURSOR", 1: "BITMAP", 2: "ICON", 3: "MENU",
		4: "DIALOG", 5: "STRING", 6: "FONTDIR", 7: "FONT",
		8: "ACCELERATOR", 9: "RCDATA", 10: "MESSAGETABLE",
		11: "GROUP_CURSOR", 12: "GROUP_ICON", 14: "VERSION",
		16: "PLUGPLAY", 17: "VXD", 19: "ANICURSOR",
		20: "ANIICON", 21: "HTML", 23: "MANIFEST",
		24: "LINK_INFO",
	}
	if name, ok := categories[index]; ok {
		return name
	}
	return fmt.Sprintf("RES_%d", index)
}

func detectResourceType(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	if len(data) > 8 && data[0] == 'V' && data[1] == 'S' && data[2] == '_' && data[3] == 'V' {
		return "VERSION_INFO"
	}
	if len(data) > 12 && string(data[:10]) == "<?xml vers" {
		return "XML_MANIFEST"
	}
	if len(data) > 40 && data[0] == 'M' && data[1] == 'Z' {
		return "EMBEDDED_PE"
	}
	if len(data) > 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00 {
		return "ICON_GROUP"
	}
	return ""
}

func walkImportDescriptors(data []byte, importRVA uint32, sections []PESection, is64 bool) []ImportDLL {
	var result []ImportDLL
	off := rvaToOffset(importRVA, sections, 0)
	if off < 0 || off+20 > len(data) {
		return nil
	}

	for {
		if off+20 > len(data) {
			break
		}

		nameRVA := binary.LittleEndian.Uint32(data[off+12 : off+16])
		if nameRVA == 0 {
			break
		}

		originalFT := binary.LittleEndian.Uint32(data[off+0 : off+4])
		firstFT := binary.LittleEndian.Uint32(data[off+16 : off+20])

		iatRVA := originalFT
		if iatRVA == 0 {
			iatRVA = firstFT
		}

		dll := ImportDLL{}
		nameOff := rvaToOffset(nameRVA, sections, 0)
		if nameOff >= 0 && nameOff < len(data)-1 {
			dll.Name = extractCString(data, nameOff)
		}

		if iatRVA > 0 {
			iatOff := rvaToOffset(iatRVA, sections, 0)
			if iatOff >= 0 {
				if is64 {
					walkThunks64(data, iatOff, &dll)
				} else {
					walkThunks32(data, iatOff, &dll)
				}
			}
		}

		if dll.Name != "" {
			result = append(result, dll)
		}
		off += 20
	}

	return result
}

func walkThunks32(data []byte, off int, dll *ImportDLL) {
	for off+4 <= len(data) {
		thunk := binary.LittleEndian.Uint32(data[off : off+4])
		if thunk == 0 {
			break
		}
		if thunk&imageOrdinalFlag32 != 0 {
			ordinal := thunk & 0x7FFFFFFF
			dll.Imports = append(dll.Imports, fmt.Sprintf("ordinal_%d", ordinal))
			dll.Ordinal = true
		} else {
			nameOff := int(thunk)
			if nameOff+2 < len(data) {
				name := extractCString(data, nameOff+2)
				if name != "" {
					dll.Imports = append(dll.Imports, name)
				}
			}
		}
		off += 4
	}
}

func walkThunks64(data []byte, off int, dll *ImportDLL) {
	for off+8 <= len(data) {
		thunk := binary.LittleEndian.Uint64(data[off : off+8])
		if thunk == 0 {
			break
		}
		if thunk&imageOrdinalFlag64 != 0 {
			ordinal := thunk & 0x7FFFFFFFFFFFFFFF
			dll.Imports = append(dll.Imports, fmt.Sprintf("ordinal_%d", ordinal))
			dll.Ordinal = true
		} else {
			nameOff := int(thunk)
			if nameOff >= 0 && nameOff+2 < len(data) {
				name := extractCString(data, nameOff+2)
				if name != "" {
					dll.Imports = append(dll.Imports, name)
				}
			}
		}
		off += 8
	}
}

func extractCString(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off
	for end < len(data) && data[end] != 0 && end-off < 256 {
		end++
	}
	return string(data[off:end])
}

func (pe *PEMemory) detectPacker() {
	score := 0.0
	if len(pe.Sections) == 0 {
		return
	}

	// Strong signal: known packer section names
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
		case ".tGzU":
			pe.PackerName = "tGzU Packer"; score = 0.9
		case ".adata", ".udata":
			// Common in packed/malformed PEs
			if s.Entropy > 6.0 {
				score += 0.3
			}
		}
		if pe.PackerName != "" {
			pe.IsPacked = true
			pe.PackerConf = score
			return
		}
	}

	// Scoring-based detection
	for _, s := range pe.Sections {
		if s.Name != "" && len(s.Name) > 8 {
			score += 0.25
			pe.SuspiciousSections++
		}
		if s.Name == "" && s.RawSize > 0 {
			score += 0.2
		}
	}

	highEntropy := 0
	for _, s := range pe.Sections {
		if s.Entropy > 7.0 && s.RawSize > 2048 {
			highEntropy++
		}
	}
	score += float64(highEntropy) * 0.2

	if len(pe.Sections) > 1 {
		last := pe.Sections[len(pe.Sections)-1]
		epInLast := pe.EntryPoint >= last.VirtualAddr &&
			pe.EntryPoint < last.VirtualAddr+last.VirtualSize
		if epInLast && last.Entropy > 6.5 {
			score += 0.3
		}
	}

	totalImports := 0
	for _, d := range pe.Imports {
		totalImports += len(d.Imports)
	}
	if totalImports < 5 && len(pe.Sections) > 2 {
		score += 0.3
	}
	if pe.HasTLS && totalImports < 10 {
		score += 0.2
	}
	if len(pe.Sections) > 0 && pe.Sections[0].Entropy > 7.0 {
		score += 0.2
	}

	if score >= 0.6 {
		pe.IsPacked = true
		pe.PackerConf = score
		if pe.PackerName == "" && highEntropy > 1 {
			pe.PackerName = "VMProtect/Confuser"
		} else if pe.PackerName == "" {
			pe.PackerName = "Unknown Packer"
		}
	}
}

func cstring(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
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
