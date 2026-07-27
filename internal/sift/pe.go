package sift

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
)

type PEMetadata struct {
	IsPE          bool        `json:"is_pe"`
	MD5           string      `json:"md5"`
	SHA1          string      `json:"sha1"`
	SHA256        string      `json:"sha256"`
	FileSize      int64       `json:"file_size"`
	CompileTime   string      `json:"compile_timestamp"`
	EntryPoint    string      `json:"entry_point"`
	ImageBase     uint64      `json:"image_base"`
	Subsystem     string      `json:"subsystem"`
	Sections      []PESection `json:"sections"`
	Imports       []string    `json:"imports"`
	Exports       []string    `json:"exports,omitempty"`
	Suspicious    []string    `json:"suspicious"`
	Entropy       float64     `json:"entropy"`
	HighEntropy   bool        `json:"high_entropy"`

	IsDLL              bool   `json:"is_dll"`
	DllCharacteristics string `json:"dll_characteristics,omitempty"`

	VersionInfo string `json:"version_info,omitempty"`
	Manifest    string `json:"manifest,omitempty"`
	PDBPath     string `json:"pdb_path,omitempty"`
	Signed      bool   `json:"signed"`
	SignerInfo  string `json:"signer_info,omitempty"`
	OverlaySize int64  `json:"overlay_size,omitempty"`
	IsManaged   bool   `json:"is_managed"`
	RichHeader  string `json:"rich_header,omitempty"`
}

type PESection struct {
	Name        string  `json:"name"`
	VirtualSize uint32  `json:"virtual_size"`
	RawSize     uint32  `json:"raw_size"`
	Entropy     float64 `json:"entropy"`
	Flags       string  `json:"flags"`
	Offset      int64   `json:"offset"`
}

type PESectionInfo struct {
	Name   string
	Offset int64
}

func AnalyzePE(path string) (*PEMetadata, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	meta := &PEMetadata{
		FileSize: stat.Size(),
	}

	meta.MD5 = fmt.Sprintf("%02x", md5.Sum(data))
	meta.SHA1 = fmt.Sprintf("%02x", sha1.Sum(data))
	meta.SHA256 = fmt.Sprintf("%02x", sha256.Sum256(data))

	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return meta, nil
	}

	meta.IsPE = true
	meta.Subsystem = "unknown"

	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	if eLfanew+4 >= int64(len(data)) || data[eLfanew] != 'P' || data[eLfanew+1] != 'E' {
		return meta, nil
	}

	coffOffset := eLfanew + 4
	if coffOffset+20 > int64(len(data)) {
		return meta, nil
	}

	machine := binary.LittleEndian.Uint16(data[coffOffset:])
	switch machine {
	case 0x8664:
		meta.Subsystem = "x64"
	case 0x14c:
		meta.Subsystem = "x86"
	case 0x1c0:
		meta.Subsystem = "ARM"
	case 0xaa64:
		meta.Subsystem = "ARM64"
	default:
		meta.Subsystem = fmt.Sprintf("0x%04x", machine)
	}

	// COFF characteristics — DLL flag
	coffChar := binary.LittleEndian.Uint16(data[coffOffset+18:])
	meta.IsDLL = coffChar&0x2000 != 0

	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsHeaderSize := int64(binary.LittleEndian.Uint16(data[coffOffset+16:]))
	optionalOffset := coffOffset + 20

	if optionalOffset+optsHeaderSize > int64(len(data)) {
		return meta, nil
	}

	peMagic := binary.LittleEndian.Uint16(data[optionalOffset:])
	pePlus := peMagic == 0x20b

	if pePlus {
		if optionalOffset+120 <= int64(len(data)) {
			entryLow := binary.LittleEndian.Uint32(data[optionalOffset+16:])
			entryHigh := binary.LittleEndian.Uint32(data[optionalOffset+20:])
			meta.EntryPoint = fmt.Sprintf("0x%04x%08x", entryHigh, entryLow)
			meta.ImageBase = binary.LittleEndian.Uint64(data[optionalOffset+24:])
			ts := int64(binary.LittleEndian.Uint32(data[optionalOffset+112:]))
			if ts > 0 {
				meta.CompileTime = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
			// DLL characteristics at offset 70 in PE32+ optional header
			dllChar := binary.LittleEndian.Uint16(data[optionalOffset+70:])
			meta.DllCharacteristics = decodeDllCharacteristics(dllChar)
		}
	} else {
		if optionalOffset+72 <= int64(len(data)) {
			meta.EntryPoint = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(data[optionalOffset+16:]))
			meta.ImageBase = uint64(binary.LittleEndian.Uint32(data[optionalOffset+28:]))
			ts := int64(binary.LittleEndian.Uint32(data[optionalOffset+64:]))
			if ts > 0 {
				meta.CompileTime = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
			// DLL characteristics at offset 70 in PE32 optional header
			dllChar := binary.LittleEndian.Uint16(data[optionalOffset+70:])
			meta.DllCharacteristics = decodeDllCharacteristics(dllChar)
		}
	}

	// Rich Header
	if rh := parseRichHeader(data, eLfanew); rh != "" {
		meta.RichHeader = rh
	}

	// .NET CLR header detection
	clrDirOffset := optionalOffset
	if pePlus {
		clrDirOffset += 80 + 14*8 // data directory entry 14 (CLR) at offset 80 + 14*8
	} else {
		clrDirOffset += 72 + 14*8
	}
	if clrDirOffset+8 <= int64(len(data)) {
		clrRVA := binary.LittleEndian.Uint32(data[clrDirOffset:])
		if clrRVA != 0 {
			meta.IsManaged = true
		}
	}

	sectionsOffset := optionalOffset + optsHeaderSize
	if sectionsOffset > int64(len(data)) {
		return meta, nil
	}

	// Overlay detection: data after the last section's raw end
	var lastSectionEnd int64
	var exportRVA, exportSize uint32

	totalEntropy := 0.0
	for i := 0; i < numSections; i++ {
		secOff := sectionsOffset + int64(i)*40
		if secOff+40 > int64(len(data)) {
			break
		}

		rawDataOffset := int64(binary.LittleEndian.Uint32(data[secOff+20:]))
		rawSize := binary.LittleEndian.Uint32(data[secOff+16:])
		secEnd := rawDataOffset + int64(rawSize)
		if secEnd > lastSectionEnd {
			lastSectionEnd = secEnd
		}

		var sec PESection
		nameBytes := data[secOff : secOff+8]
		sec.Name = strings.TrimRight(string(nameBytes), "\x00 ")
		sec.VirtualSize = binary.LittleEndian.Uint32(data[secOff+8:])
		sec.RawSize = rawSize
		sec.Offset = rawDataOffset

		flags := binary.LittleEndian.Uint32(data[secOff+36:])
		var flagStrs []string
		if flags&0x20 != 0 {
			flagStrs = append(flagStrs, "CODE")
		}
		if flags&0x40 != 0 {
			flagStrs = append(flagStrs, "INIT_DATA")
		}
		if flags&0x80 != 0 {
			flagStrs = append(flagStrs, "UNINIT_DATA")
		}
		if flags&0x20000000 != 0 {
			flagStrs = append(flagStrs, "EXECUTE")
		}
		if flags&0x40000000 != 0 {
			flagStrs = append(flagStrs, "READ")
		}
		if flags&0x80000000 != 0 {
			flagStrs = append(flagStrs, "WRITE")
		}
		sec.Flags = strings.Join(flagStrs, "|")

		if rawDataOffset > 0 && int(rawDataOffset)+int(rawSize) <= len(data) && rawSize > 0 {
			secData := data[rawDataOffset : rawDataOffset+int64(rawSize)]
			sec.Entropy = calculateEntropy(secData)
			totalEntropy += sec.Entropy

			// Per-section entropy threshold
			if sec.Entropy > 7.0 {
				meta.Suspicious = append(meta.Suspicious,
					fmt.Sprintf("High entropy section %q (%.2f)", sec.Name, sec.Entropy))
			}
		}

		meta.Sections = append(meta.Sections, sec)

		hasNonPrintable := false
		for _, b := range nameBytes {
			if b < 32 && b != 0 || b > 126 {
				hasNonPrintable = true
				break
			}
		}
		if hasNonPrintable {
			meta.Suspicious = append(meta.Suspicious, fmt.Sprintf("Suspicious section name: %q", sec.Name))
		}

		// Collect export RVA from data directory (PE32: offset 72+8, PE32+: offset 80+8)
		if pePlus && i == 0 {
			exportDirOffset := optionalOffset + 80 + 8
			if exportDirOffset+8 <= int64(len(data)) {
				exportRVA = binary.LittleEndian.Uint32(data[exportDirOffset:])
				exportSize = binary.LittleEndian.Uint32(data[exportDirOffset+4:])
			}
		} else if i == 0 {
			exportDirOffset := optionalOffset + 72 + 8
			if exportDirOffset+8 <= int64(len(data)) {
				exportRVA = binary.LittleEndian.Uint32(data[exportDirOffset:])
				exportSize = binary.LittleEndian.Uint32(data[exportDirOffset+4:])
			}
		}
	}

	// Per-section high-entropy vs overall
	if len(meta.Sections) > 0 {
		meta.Entropy = math.Round(totalEntropy/float64(len(meta.Sections))*100) / 100
		meta.HighEntropy = meta.Entropy > 7.0
		if meta.HighEntropy {
			meta.Suspicious = append(meta.Suspicious, fmt.Sprintf("High entropy (%.2f) — possible packed/encrypted", meta.Entropy))
		}
	}

	if meta.CompileTime != "" {
		ct, err := time.Parse(time.RFC3339, meta.CompileTime)
		if err == nil {
			if time.Since(ct) > 365*24*time.Hour {
				meta.Suspicious = append(meta.Suspicious, fmt.Sprintf("Old compile timestamp (%s) — possible malware masquerading", meta.CompileTime))
			}
			if ct.After(time.Now().Add(24*time.Hour)) || ct.Year() < 2000 {
				meta.Suspicious = append(meta.Suspicious, fmt.Sprintf("Suspicious compile timestamp (%s)", meta.CompileTime))
			}
		}
	}

	imports, err := parsePEImportTable(data)
	if err == nil && len(imports) > 0 {
		meta.Imports = imports
	}

	// Export table
	if exportRVA != 0 && exportSize > 0 {
		exportOffset := rvaToOffset(exportRVA, data, sectionsOffset, numSections)
		if exportOffset > 0 {
			if exports := parseExportTable(data, exportOffset); len(exports) > 0 {
				meta.Exports = exports
			}
		}
	}

	// Overlay
	if lastSectionEnd > 0 && lastSectionEnd < int64(len(data)) {
		meta.OverlaySize = int64(len(data)) - lastSectionEnd
	}

	// Resource directory (parse .rsrc section for version info and manifest)
	for _, sec := range meta.Sections {
		if sec.Name == ".rsrc" && int(sec.Offset)+int(sec.RawSize) <= len(data) {
			rsrcData := data[sec.Offset : sec.Offset+int64(sec.RawSize)]
			parseResourceDirectory(meta, rsrcData)
		}
	}

	// Debug directory
	parseDebugDirectory(meta, data, optionalOffset, pePlus, sectionsOffset, numSections)

	// Digital signature (Authenticode)
	detectAuthenticode(meta, data, lastSectionEnd)

	return meta, nil
}

func decodeDllCharacteristics(v uint16) string {
	var parts []string
	if v&0x0040 != 0 {
		parts = append(parts, "ASLR")
	}
	if v&0x0080 != 0 {
		parts = append(parts, "DEP")
	}
	if v&0x0100 != 0 {
		parts = append(parts, "INTEGRITY")
	}
	if v&0x0200 != 0 {
		parts = append(parts, "NX")
	}
	if v&0x0400 != 0 {
		parts = append(parts, "NX_EDIT")
	}
	if v&0x0800 != 0 {
		parts = append(parts, "NO_BIND")
	}
	if v&0x1000 != 0 {
		parts = append(parts, "APPCONTAINER")
	}
	if v&0x2000 != 0 {
		parts = append(parts, "WDM_DRIVER")
	}
	if v&0x4000 != 0 {
		parts = append(parts, "GUARD_CF")
	}
	if v&0x8000 != 0 {
		parts = append(parts, "TERSERVE")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

func parseRichHeader(data []byte, eLfanew int64) string {
	// Rich header is between DOS stub end and PE signature.
	// Format: XOR-encrypted DWORDs with key being the last DWORD before "Rich".
	// We look for "Rich" marker, find the key, decrypt preceding DWORDs.
	if eLfanew < 128 {
		return ""
	}
	richArea := data[128:eLfanew] // between DOS stub and PE sig
	if len(richArea) < 8 {
		return ""
	}

	richPos := -1
	for i := 0; i <= len(richArea)-4; i++ {
		if richArea[i] == 'R' && richArea[i+1] == 'i' && richArea[i+2] == 'c' && richArea[i+3] == 'h' {
			richPos = i
			break
		}
	}
	if richPos < 4 {
		return ""
	}

	// Key is the DWORD before "Rich"
	key := binary.LittleEndian.Uint32(richArea[richPos-4:])
	if key == 0 {
		return ""
	}

	var parts []string
	for i := 0; i < richPos-4; i += 8 {
		if i+8 > richPos-4 {
			break
		}
		compID := binary.LittleEndian.Uint32(richArea[i:]) ^ key
		count := binary.LittleEndian.Uint32(richArea[i+4:]) ^ key
		if compID == 0 {
			continue
		}
		prodID := compID & 0xFFFF
		buildID := compID >> 16
		parts = append(parts, fmt.Sprintf("prod=%d/build=%d/count=%d", prodID, buildID, count))
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

func parseExportTable(data []byte, exportOffset int64) []string {
	if exportOffset+40 > int64(len(data)) {
		return nil
	}

	numFns := int(binary.LittleEndian.Uint32(data[exportOffset+20:]))
	addrRVA := binary.LittleEndian.Uint32(data[exportOffset+28:])
	nameRVA := binary.LittleEndian.Uint32(data[exportOffset+32:])

	if numFns == 0 || addrRVA == 0 || nameRVA == 0 {
		return nil
	}

	var names []string
	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	coffOffset := eLfanew + 4
	numSects := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsSize := int64(binary.LittleEndian.Uint16(data[coffOffset+16:]))
	secOff := coffOffset + 20 + optsSize

	nameTableOff := rvaToOffset(nameRVA, data, secOff, numSects)
	if nameTableOff == 0 {
		return nil
	}

	ordBase := binary.LittleEndian.Uint32(data[exportOffset+16:])
	for i := 0; i < numFns; i++ {
		off := nameTableOff + int64(i)*4
		if off+4 > int64(len(data)) {
			break
		}
		nameAddr := binary.LittleEndian.Uint32(data[off:])
		if nameAddr != 0 {
			nameOff := rvaToOffset(nameAddr, data, secOff, numSects)
			if nameOff > 0 {
				if name := readCString(data, nameOff); name != "" {
					names = append(names, name)
				}
			}
		}
	}
	_ = ordBase
	return names
}

func parseResourceDirectory(meta *PEMetadata, rsrcData []byte) {
	if len(rsrcData) < 16 {
		return
	}
	// Walk type-level entries looking for VERSION (16) and MANIFEST (24)
	numEntries := int(binary.LittleEndian.Uint16(rsrcData[12:]))
	entryOffset := 16
	for i := 0; i < numEntries && entryOffset+8 <= len(rsrcData); i++ {
		typeID := binary.LittleEndian.Uint32(rsrcData[entryOffset:])
		entryData := binary.LittleEndian.Uint32(rsrcData[entryOffset+4:])

		switch typeID {
		case 16: // RT_VERSION
			if ver := readVersionInfo(rsrcData, entryData); ver != "" {
				meta.VersionInfo = ver
			}
		case 24: // RT_MANIFEST
			if manifest := readManifest(rsrcData, entryData); manifest != "" {
				meta.Manifest = manifest
			}
		}
		entryOffset += 8
	}
}

func readVersionInfo(data []byte, entry uint32) string {
	// entry is a 3-level directory: high bit = data entry, otherwise subdirectory
	if entry&0x80000000 == 0 {
		return ""
	}
	subDirOffset := int(entry & 0x7FFFFFFF)
	// Look for the first leaf entry (language entry)
	leafOffset := findFirstLeaf(data, subDirOffset)
	if leafOffset < 0 || leafOffset+16 > len(data) {
		return ""
	}
	// Data entry: offset at data[leafOffset+8], size at data[leafOffset+12]
	resOffset := int(binary.LittleEndian.Uint32(data[leafOffset+8:]))
	resSize := int(binary.LittleEndian.Uint32(data[leafOffset+12:]))
	if resOffset+resSize > len(data) || resSize < 52 {
		return ""
	}
	verData := data[resOffset : resOffset+resSize]
	// VS_VERSIONINFO: root has 16-byte VS_FIXEDFILEINFO at offset 24+
	if len(verData) < 48 {
		return ""
	}
	ms := binary.LittleEndian.Uint32(verData[24:])
	ls := binary.LittleEndian.Uint32(verData[28:])
	return fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xFFFF, ls>>16, ls&0xFFFF)
}

func readManifest(data []byte, entry uint32) string {
	if entry&0x80000000 == 0 {
		return ""
	}
	subDirOffset := int(entry & 0x7FFFFFFF)
	leafOffset := findFirstLeaf(data, subDirOffset)
	if leafOffset < 0 || leafOffset+16 > len(data) {
		return ""
	}
	resOffset := int(binary.LittleEndian.Uint32(data[leafOffset+8:]))
	resSize := int(binary.LittleEndian.Uint32(data[leafOffset+12:]))
	if resOffset+resSize > len(data) || resSize <= 0 {
		return ""
	}
	// Truncate long manifests
	if resSize > 2000 {
		resSize = 2000
	}
	return strings.TrimSpace(string(data[resOffset : resOffset+resSize]))
}

func findFirstLeaf(data []byte, offset int) int {
	if offset+16 > len(data) {
		return -1
	}
	numEntries := int(binary.LittleEndian.Uint16(data[offset+12:]))
	entryOffset := offset + 16
	for i := 0; i < numEntries && entryOffset+8 <= len(data); i++ {
		entry := binary.LittleEndian.Uint32(data[entryOffset+4:])
		if entry&0x80000000 != 0 {
			sub := int(entry & 0x7FFFFFFF)
			if leaf := findFirstLeaf(data, sub); leaf >= 0 {
				return leaf
			}
		} else {
			return int(entry) // leaf data entry
		}
		entryOffset += 8
	}
	return -1
}

func parseDebugDirectory(meta *PEMetadata, data []byte, optionalOffset int64, pePlus bool, sectionsOffset int64, numSections int) {
	// Debug directory is data directory entry 6
	var dbgDirOffset int64
	if pePlus {
		dbgDirOffset = optionalOffset + 80 + 6*8
	} else {
		dbgDirOffset = optionalOffset + 72 + 6*8
	}
	if dbgDirOffset+8 > int64(len(data)) {
		return
	}
	dbgRVA := binary.LittleEndian.Uint32(data[dbgDirOffset:])
	dbgSize := int64(binary.LittleEndian.Uint32(data[dbgDirOffset+4:]))
	if dbgRVA == 0 || dbgSize < 28 {
		return
	}
	dbgOff := rvaToOffset(dbgRVA, data, sectionsOffset, numSections)
	if dbgOff == 0 {
		return
	}
	// Parse CV_INFO_PDB70 (NB10 or RSDS format)
	for off := dbgOff; off+28 <= dbgOff+dbgSize && off+28 <= int64(len(data)); off += 28 {
		dbgType := binary.LittleEndian.Uint32(data[off:])
		if dbgType == 0x53445352 { // RSDS ("SDSR" = CodeView v2)
			pdbOff := off + 24
			if pdbOff < int64(len(data)) {
				meta.PDBPath = readCString(data, pdbOff)
				return
			}
		}
	}
}

func detectAuthenticode(meta *PEMetadata, data []byte, lastSectionEnd int64) {
	// Authenticode signature is at the end of the file: a PKCS#7 ContentInfo
	// wrapped in IMAGE_DIRECTORY_ENTRY_SECURITY (entry 4) in data directory.
	// But we can also detect it by looking for a PKCS#7 blob at the end.
	if lastSectionEnd <= 0 || lastSectionEnd >= int64(len(data)) {
		return
	}
	// Check for PKCS#7 signature marker at the overlayed data start
	overlay := data[lastSectionEnd:]
	if len(overlay) < 8 {
		return
	}
	// PKCS#7 ContentInfo starts with SEQUENCE (0x30) tag following WIN_CERTIFICATE header
	if overlay[0] == 0x30 && overlay[1] != 0 {
		// Likely contains Authenticode
		meta.Signed = true
		// Try to extract the signer organization name
		if sigInfo := extractSignerInfo(overlay); sigInfo != "" {
			meta.SignerInfo = sigInfo
		}
		return
	}
	// Also check for WIN_CERTIFICATE header (dwCertificateType = 2 for Authenticode)
	if len(overlay) >= 8 && binary.LittleEndian.Uint32(overlay[4:]) == 2 {
		meta.Signed = true
		// Follow wCertificateLength to find PKCS#7 blob
		certLen := int64(binary.LittleEndian.Uint32(overlay[0:]))
		if certLen > 8 && certLen <= int64(len(overlay)) {
			if sigInfo := extractSignerInfo(overlay[8:certLen]); sigInfo != "" {
				meta.SignerInfo = sigInfo
			}
		}
	}
}

func extractSignerInfo(data []byte) string {
	// Minimal PKCS#7 signer info extraction.
	// Look for commonName/O in the ASN.1 DER data.
	idx := 0
	for idx < len(data)-6 {
		if data[idx] == 0x30 { // SEQUENCE
			idx += 2 + int(data[idx+1])
			continue
		}
		if data[idx] == 0x16 { // IA5String
			strLen := int(data[idx+1])
			if idx+2+strLen <= len(data) && strLen > 1 && strLen < 100 {
				return string(data[idx+2 : idx+2+strLen])
			}
		}
		idx++
	}
	return ""
}

func parsePESections(data []byte) ([]PESectionInfo, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("data too short for DOS header")
	}
	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' || eLfanew+4 >= int64(len(data)) || data[eLfanew] != 'P' || data[eLfanew+1] != 'E' {
		return nil, fmt.Errorf("not a PE file")
	}

	coffOffset := eLfanew + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsHeaderSize := int64(binary.LittleEndian.Uint16(data[coffOffset+16:]))
	optionalOffset := coffOffset + 20

	sectionsOffset := optionalOffset + optsHeaderSize

	var sections []PESectionInfo
	for i := 0; i < numSections; i++ {
		secOff := sectionsOffset + int64(i)*40
		if secOff+40 > int64(len(data)) {
			break
		}
		nameBytes := data[secOff : secOff+8]
		name := strings.TrimRight(string(nameBytes), "\x00 ")
		rawDataOffset := int64(binary.LittleEndian.Uint32(data[secOff+20:]))

		sections = append(sections, PESectionInfo{
			Name:   name,
			Offset: rawDataOffset,
		})
	}

	if len(sections) == 0 {
		return nil, fmt.Errorf("no sections found")
	}

	return sections, nil
}

func parsePEImportTable(data []byte) ([]string, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("data too short")
	}
	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	if len(data) < 256 || data[0] != 'M' || data[1] != 'Z' || eLfanew+4 >= int64(len(data)) || data[eLfanew] != 'P' || data[eLfanew+1] != 'E' {
		return nil, fmt.Errorf("not a PE file")
	}

	coffOffset := eLfanew + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsHeaderSize := int64(binary.LittleEndian.Uint16(data[coffOffset+16:]))
	optionalOffset := coffOffset + 20

	if optionalOffset+optsHeaderSize > int64(len(data)) {
		return nil, fmt.Errorf("optional header truncated")
	}

	peMagic := binary.LittleEndian.Uint16(data[optionalOffset:])
	pePlus := peMagic == 0x20b

	sectionsOffset := optionalOffset + optsHeaderSize
	var importRVADirOffset int64

	if pePlus {
		importRVADirOffset = optionalOffset + 80 + 16
	} else {
		importRVADirOffset = optionalOffset + 72 + 16
	}

	if importRVADirOffset+8 > int64(len(data)) {
		return nil, fmt.Errorf("data directory truncated")
	}

	importRVA := binary.LittleEndian.Uint32(data[importRVADirOffset:])
	if importRVA == 0 {
		return nil, fmt.Errorf("no imports")
	}

	importOffset := rvaToOffset(importRVA, data, sectionsOffset, numSections)
	if importOffset == 0 || importOffset >= int64(len(data)) {
		return nil, fmt.Errorf("invalid import offset")
	}

	var imports []string
	for {
		if importOffset+20 > int64(len(data)) {
			break
		}

		nameRVA := binary.LittleEndian.Uint32(data[importOffset+12:])
		if nameRVA == 0 {
			break
		}

		nameOffset := rvaToOffset(nameRVA, data, sectionsOffset, numSections)
		if nameOffset > 0 && nameOffset < int64(len(data)) {
			name := readCString(data, nameOffset)
			if name != "" {
				imports = append(imports, name)
			}
		}

		importOffset += 20
	}

	return imports, nil
}

func rvaToOffset(rva uint32, data []byte, sectionOffset int64, numSections int) int64 {
	for i := 0; i < numSections; i++ {
		secOff := sectionOffset + int64(i)*40
		if secOff+40 > int64(len(data)) {
			break
		}

		virtualAddr := binary.LittleEndian.Uint32(data[secOff+12:])
		rawSize := binary.LittleEndian.Uint32(data[secOff+16:])
		rawOffset := int64(binary.LittleEndian.Uint32(data[secOff+20:]))

		if rva >= virtualAddr && rawSize > 0 && rva < virtualAddr+rawSize {
			return rawOffset + int64(rva-virtualAddr)
		}
	}
	return 0
}

func readCString(data []byte, offset int64) string {
	var b []byte
	for i := offset; i < int64(len(data)); i++ {
		if data[i] == 0 {
			break
		}
		b = append(b, data[i])
	}
	return string(b)
}

func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	entropy := 0.0
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return math.Round(entropy*100) / 100
}
