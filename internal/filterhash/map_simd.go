//go:build goexperiment.simd && amd64 && !purego

package filterhash

import (
	"encoding/binary"
	"math/bits"
	"simd/archsimd"
)

const (
	lanes     = 8
	minRun    = 2 * lanes
	minLength = 8
	maxLength = 40
)

func mapToRange(dst []uint64, key *[16]byte, modulus uint64, scripts [][]byte) {
	if len(scripts) < minRun || !archsimd.X86.AVX512() {
		mapScalar(dst, key, modulus, scripts)
		return
	}

	// Group contiguous runs so all lanes perform the same number of rounds
	// with the same tail size. Hash smaller runs and leftover scripts together
	// with the scalar implementation, outside the vector loop.
	scalarStart := 0
	for start := 0; start <= len(scripts)-minRun; {
		length := len(scripts[start])
		end := start + 1
		for end < len(scripts) && len(scripts[end]) == length {
			end++
		}
		if end-start >= minRun && length >= minLength && length <= maxLength {
			batchEnd := start + ((end - start) &^ (lanes - 1))
			mapScalar(dst[scalarStart:start], key, modulus,
				scripts[scalarStart:start])
			mapSIMDBatches(dst[start:batchEnd], key, modulus,
				scripts[start:batchEnd], length)
			scalarStart = batchEnd
		}
		start = end
	}
	mapScalar(dst[scalarStart:], key, modulus, scripts[scalarStart:])
}

// mapSIMDBatches takes a multiple of eight equal-length scripts.
func mapSIMDBatches(dst []uint64, key *[16]byte, modulus uint64,
	scripts [][]byte, length int) {

	var words [lanes]uint64
	k0 := binary.LittleEndian.Uint64(key[:8])
	k1 := binary.LittleEndian.Uint64(key[8:])
	s0 := archsimd.BroadcastUint64x8(k0 ^ 0x736f6d6570736575)
	s1 := archsimd.BroadcastUint64x8(k1 ^ 0x646f72616e646f6d)
	s2 := archsimd.BroadcastUint64x8(k0 ^ 0x6c7967656e657261)
	s3 := archsimd.BroadcastUint64x8(k1 ^ 0x7465646279746573)
	final := archsimd.BroadcastUint64x8(0xff)
	full := length &^ 7
	shift := uint(8-(length&7)) * 8
	for len(scripts) >= lanes {
		batch := scripts[:lanes]

		v0, v1, v2, v3 := s0, s1, s2, s3
		for offset := 0; offset < full; offset += 8 {
			for lane, script := range batch {
				words[lane] = binary.LittleEndian.Uint64(script[offset:])
			}
			m := loadVector(&words)
			v0, v1, v2, v3 = sipCompress(v0, v1, v2, v3, m)
		}

		// SipHash puts the message length in the high byte of the final
		// word. The other bytes contain the remaining message bytes in
		// little-endian order, padded with zeros.
		for lane, script := range batch {
			tail := binary.LittleEndian.Uint64(script[length-8:])
			words[lane] = uint64(length)<<56 | tail>>shift
		}
		m := loadVector(&words)
		v0, v1, v2, v3 = sipCompress(v0, v1, v2, v3, m)
		v2 = v2.Xor(final)
		for round := 0; round < 4; round++ {
			v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		}
		storeVector(v0.Xor(v1).Xor(v2).Xor(v3), &words)
		// Iterating over a slice avoids copying the vector-sized array.
		for lane, hash := range words[:] {
			dst[lane], _ = bits.Mul64(hash, modulus)
		}
		dst, scripts = dst[lanes:], scripts[lanes:]
	}
}

func sipCompress(v0, v1, v2, v3, message archsimd.Uint64x8) (
	archsimd.Uint64x8, archsimd.Uint64x8, archsimd.Uint64x8, archsimd.Uint64x8) {

	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3.Xor(message))
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	return v0.Xor(message), v1, v2, v3
}

func sipRound(v0, v1, v2, v3 archsimd.Uint64x8) (
	archsimd.Uint64x8, archsimd.Uint64x8, archsimd.Uint64x8, archsimd.Uint64x8) {

	v0 = v0.Add(v1)
	v1 = v1.RotateAllLeft(13).Xor(v0)
	v0 = v0.RotateAllLeft(32)
	v2 = v2.Add(v3)
	v3 = v3.RotateAllLeft(16).Xor(v2)
	v0 = v0.Add(v3)
	v3 = v3.RotateAllLeft(21).Xor(v0)
	v2 = v2.Add(v1)
	v1 = v1.RotateAllLeft(17).Xor(v2)
	v2 = v2.RotateAllLeft(32)
	return v0, v1, v2, v3
}
