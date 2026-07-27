package sift

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math"
)

// peTestHelper generates synthetic PE binaries for testing.
// All fields are exported for testing convenience.

type peTestSection struct {
	Name       string
	RawSize    uint32
	RawData    []byte
	Flags      uint32 // IMAGE_SCN_*
}

const (
	imgScnCntCode        uint32 = 0x00000020
	imgScnCntInitData    uint32 = 0x00000040
	imgScnMemExecute     uint32 = 0x20000000
	imgScnMemRead        uint32 = 0x40000000
	imgScnMemWrite       uint32 = 0x80000000
	imgFileDLL           uint16 = 0x2000
	imgFileRelocsStripped uint16 = 0x0001
	imgFileExecutable    uint16 = 0x0002
	imgFile32BitMachine  uint16 = 0x0100

	dllCharacteristics uint16 = 0x0140 // ASLR + DEP + NX
)

func buildPE32(sections []peTestSection, isDLL bool, entryPoint uint32, compileTime uint32) []byte {
	return buildPE(pe32Magic, 0x10b, sections, isDLL, entryPoint, compileTime)
}

func buildPE64(sections []peTestSection, isDLL bool, entryPoint uint32, compileTime uint32) []byte {
	return buildPE(pe64Magic, 0x20b, sections, isDLL, entryPoint, compileTime)
}

const (
	pe32Magic = 0x14c
	pe64Magic = 0x8664
)

func buildPE(machine uint16, peMagic uint16, sections []peTestSection, isDLL bool, entryPoint, compileTime uint32) []byte {
	var data []byte

	// DOS header
	dosHead := make([]byte, 64)
	dosHead[0] = 'M'
	dosHead[1] = 'Z'
	eLfanew := uint32(128) // PE signature after DOS + stub
	binary.LittleEndian.PutUint32(dosHead[60:], eLfanew)
	data = append(data, dosHead...)

	// Stub
	stub := make([]byte, 64)
	data = append(data, stub...)

	// PE signature
	peSig := []byte("PE\x00\x00")
	data = append(data, peSig...)

	// COFF header (20 bytes)
	coffStart := len(data)
	coffHead := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffHead[0:], machine) // machine
	numSects := uint16(len(sections))
	binary.LittleEndian.PutUint16(coffHead[2:], numSects) // number of sections
	var characteristics uint16 = imgFileExecutable | imgFile32BitMachine
	if isDLL {
		characteristics |= imgFileDLL
	}
	binary.LittleEndian.PutUint16(coffHead[18:], characteristics)
	// time/pointer/symbol fields left as 0
	data = append(data, coffHead...)

	// Optional header
	var optsHeaderSize uint16
	if peMagic == 0x20b {
		optsHeaderSize = 240
	} else {
		optsHeaderSize = 224
	}
	// Update COFF header with optional header size
	binary.LittleEndian.PutUint16(data[coffStart+16:], optsHeaderSize)

	optionalStart := len(data)
	optionalHead := make([]byte, optsHeaderSize)
	binary.LittleEndian.PutUint16(optionalHead[0:], peMagic) // magic

	// Entry point
	if peMagic == 0x20b {
		binary.LittleEndian.PutUint32(optionalHead[16:], entryPoint)
		// Image base
		binary.LittleEndian.PutUint64(optionalHead[24:], 0x140000000)
		// Compile time in PE32+ (offset 112)
		binary.LittleEndian.PutUint32(optionalHead[112:], compileTime)

		// Data directory count (16)
		ddCountOffset := optionalStart + 108
		if int(ddCountOffset+4) <= len(data)+len(optionalHead) {
		}

		// Size of headers (offset 84 in PE32+)
		sizeOfHeaders := uint32(optionalStart + int(optsHeaderSize) + int(numSects)*40)
		binary.LittleEndian.PutUint32(optionalHead[84:], sizeOfHeaders)

		// Image size
		imageSize := sizeOfHeaders
		for _, s := range sections {
			if s.RawSize > imageSize {
				imageSize = s.RawSize
			}
		}
		imageSize += 4096
		binary.LittleEndian.PutUint32(optionalHead[88:], imageSize)

		// Section alignment
		binary.LittleEndian.PutUint32(optionalHead[92:], 0x1000)
		// File alignment
		binary.LittleEndian.PutUint32(optionalHead[96:], 0x200)

		// DLL characteristics (offset 70 in PE32+)
		binary.LittleEndian.PutUint16(optionalHead[70:], dllCharacteristics)

		// Data directory import RVA (offset 80+16)
		importDirStart := 80
		importDir := optionalHead[importDirStart : importDirStart+32]
		_ = importDir
	} else {
		binary.LittleEndian.PutUint32(optionalHead[16:], entryPoint)
		// Image base
		binary.LittleEndian.PutUint32(optionalHead[28:], 0x00400000)
		// Size of headers
		sizeOfHeaders := uint32(optionalStart + int(optsHeaderSize) + int(numSects)*40)
		binary.LittleEndian.PutUint32(optionalHead[84:], sizeOfHeaders)

		// Section alignment (1 section, no strict alignment needed)
		binary.LittleEndian.PutUint32(optionalHead[92:], 0x1000)
		binary.LittleEndian.PutUint32(optionalHead[96:], 0x200)

		// Compile time in PE32 (offset 64)
		if 64+4 <= len(optionalHead) {
			binary.LittleEndian.PutUint32(optionalHead[64:], compileTime)
		}

		// DLL characteristics (offset 70 in PE32)
		binary.LittleEndian.PutUint16(optionalHead[70:], dllCharacteristics)

		// Data directory import RVA (offset 72+16)
		importDirStart := 72
		_ = importDirStart
	}

	data = append(data, optionalHead...)

	// Section table
	for i, s := range sections {
		secEntry := make([]byte, 40)
		nameBytes := []byte(s.Name)
		copy(secEntry[0:], nameBytes)
		binary.LittleEndian.PutUint32(secEntry[8:], s.RawSize)  // virtual size
		binary.LittleEndian.PutUint32(secEntry[16:], s.RawSize) // raw size
		// Raw data offset — right after section table + headers
		rawOffset := uint32(len(data) + (len(sections)-i-1)*40)
		binary.LittleEndian.PutUint32(secEntry[20:], rawOffset)
		binary.LittleEndian.PutUint32(secEntry[36:], s.Flags)
		data = append(data, secEntry...)
	}

	// Section data
	for _, s := range sections {
		pad := make([]byte, int(s.RawSize))
		copy(pad, s.RawData)
		data = append(data, pad...)
	}

	return data
}

func calcMD5(data []byte) string {
	return fmt.Sprintf("%02x", md5.Sum(data))
}

func highEntropyData(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((int(seed) + i*37) % 256)
	}
	return out
}

func lowEntropyData(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = 0x90 // NOP-like low-entropy
	}
	return out
}

func calcEntropy(data []byte) float64 {
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

// validPEData returns minimal valid PE32 bytes. Hardcoded to avoid builder complexity.
func validPEData() []byte {
	// Minimal PE32: DOS header + PE sig + COFF header + optional header + 1 section
	var b []byte
	// DOS header (64 bytes)
	dos := make([]byte, 64)
	dos[0] = 'M'
	dos[1] = 'Z'
	binary.LittleEndian.PutUint32(dos[60:], 128) // e_lfanew
	b = append(b, dos...)
	// DOS stub (64 bytes)
	b = append(b, make([]byte, 64)...)
	// PE signature
	b = append(b, 'P', 'E', 0, 0)
	// COFF header (20 bytes)
	coffPos := len(b)
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], 0x14c) // i386
	binary.LittleEndian.PutUint16(coff[2:], 1)     // 1 section
	binary.LittleEndian.PutUint16(coff[16:], 224)  // optional header size
	binary.LittleEndian.PutUint16(coff[18:], 0x0102) // executable + 32-bit
	b = append(b, coff...)
	// Optional header (224 bytes for PE32)
	opts := make([]byte, 224)
	binary.LittleEndian.PutUint16(opts[0:], 0x10b) // PE32 magic
	binary.LittleEndian.PutUint32(opts[16:], 0x1000) // entry point
	binary.LittleEndian.PutUint32(opts[28:], 0x00400000) // image base
	binary.LittleEndian.PutUint32(opts[64:], 1700000000) // compile time
	binary.LittleEndian.PutUint32(opts[84:], 1024) // size of headers
	_ = coffPos
	b = append(b, opts...)
	// Section table (40 bytes per section)
	sec := make([]byte, 40)
	copy(sec[0:], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sec[8:], 256)   // virtual size
	binary.LittleEndian.PutUint32(sec[12:], 0x1000) // virtual address
	binary.LittleEndian.PutUint32(sec[16:], 256)   // raw size
	binary.LittleEndian.PutUint32(sec[20:], 512)   // raw data offset
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020) // CODE | EXECUTE | READ
	b = append(b, sec...)
	// Section data (256 bytes)
	data := make([]byte, 256)
	for i := range data {
		data[i] = 0x90
	}
	b = append(b, data...)
	return b
}
