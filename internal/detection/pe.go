package detection

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
	IsPE          bool              `json:"is_pe"`
	MD5           string            `json:"md5"`
	SHA1          string            `json:"sha1"`
	SHA256        string            `json:"sha256"`
	FileSize      int64             `json:"file_size"`
	CompileTime   string            `json:"compile_timestamp"`
	EntryPoint    string            `json:"entry_point"`
	ImageBase     uint64            `json:"image_base"`
	Subsystem     string            `json:"subsystem"`
	Sections      []PESection       `json:"sections"`
	Imports       []string          `json:"imports"`
	Suspicious    []string          `json:"suspicious"`
	Entropy       float64           `json:"entropy"`
	HighEntropy   bool              `json:"high_entropy"`
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

	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsHeaderSize := int64(binary.LittleEndian.Uint16(data[coffOffset+18:]))
	optionalOffset := coffOffset + 20

	if optionalOffset+optsHeaderSize > int64(len(data)) {
		return meta, nil
	}

	peMagic := binary.LittleEndian.Uint16(data[optionalOffset:])
	pePlus := peMagic == 0x20b

	if pePlus {
		if optionalOffset+112 <= int64(len(data)) {
			entryLow := binary.LittleEndian.Uint32(data[optionalOffset+16:])
			entryHigh := binary.LittleEndian.Uint32(data[optionalOffset+20:])
			meta.EntryPoint = fmt.Sprintf("0x%04x%08x", entryHigh, entryLow)
			meta.ImageBase = binary.LittleEndian.Uint64(data[optionalOffset+24:])
		}
		if optionalOffset+120 <= int64(len(data)) {
			ts := int64(binary.LittleEndian.Uint32(data[optionalOffset+112:]))
			if ts > 0 {
				meta.CompileTime = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
	} else {
		if optionalOffset+72 <= int64(len(data)) {
			meta.EntryPoint = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(data[optionalOffset+16:]))
			meta.ImageBase = uint64(binary.LittleEndian.Uint32(data[optionalOffset+28:]))
		}
		if optionalOffset+72 <= int64(len(data)) {
			ts := int64(binary.LittleEndian.Uint32(data[optionalOffset+64:]))
			if ts > 0 {
				meta.CompileTime = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
		}
	}

	sectionsOffset := optionalOffset + optsHeaderSize
	if sectionsOffset > int64(len(data)) {
		return meta, nil
	}

	totalEntropy := 0.0
	for i := 0; i < numSections; i++ {
		secOff := sectionsOffset + int64(i)*40
		if secOff+40 > int64(len(data)) {
			break
		}

		var sec PESection
		nameBytes := data[secOff : secOff+8]
		sec.Name = strings.TrimRight(string(nameBytes), "\x00 ")
		sec.VirtualSize = binary.LittleEndian.Uint32(data[secOff+8:])
		sec.RawSize = binary.LittleEndian.Uint32(data[secOff+16:])
		rawDataOffset := int64(binary.LittleEndian.Uint32(data[secOff+20:]))
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

		if rawDataOffset > 0 && int(rawDataOffset)+int(sec.RawSize) <= len(data) && sec.RawSize > 0 {
			secData := data[rawDataOffset : rawDataOffset+int64(sec.RawSize)]
			sec.Entropy = calculateEntropy(secData)
			totalEntropy += sec.Entropy
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
	}

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

	return meta, nil
}

func parsePESections(data []byte) ([]PESectionInfo, error) {
	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' || eLfanew+4 >= int64(len(data)) || data[eLfanew] != 'P' || data[eLfanew+1] != 'E' {
		return nil, fmt.Errorf("not a PE file")
	}

	coffOffset := eLfanew + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsHeaderSize := int64(binary.LittleEndian.Uint16(data[coffOffset+18:]))
	optionalOffset := coffOffset + 20
	peMagic := binary.LittleEndian.Uint16(data[optionalOffset:])
	pePlus := peMagic == 0x20b

	var sectionsOffset int64
	if pePlus {
		sectionsOffset = optionalOffset + optsHeaderSize
	} else {
		sectionsOffset = optionalOffset + optsHeaderSize
	}

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
	eLfanew := int64(binary.LittleEndian.Uint32(data[60:64]))
	if len(data) < 256 || data[0] != 'M' || data[1] != 'Z' || eLfanew+4 >= int64(len(data)) || data[eLfanew] != 'P' || data[eLfanew+1] != 'E' {
		return nil, fmt.Errorf("not a PE file")
	}

	coffOffset := eLfanew + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2:]))
	optsHeaderSize := int64(binary.LittleEndian.Uint16(data[coffOffset+18:]))
	optionalOffset := coffOffset + 20

	if optionalOffset+optsHeaderSize > int64(len(data)) {
		return nil, fmt.Errorf("optional header truncated")
	}

	peMagic := binary.LittleEndian.Uint16(data[optionalOffset:])
	pePlus := peMagic == 0x20b

	var sectionsOffset int64
	var importRVADirOffset int64

	if pePlus {
		sectionsOffset = optionalOffset + optsHeaderSize
		importRVADirOffset = optionalOffset + 80 + 16
	} else {
		sectionsOffset = optionalOffset + optsHeaderSize
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
