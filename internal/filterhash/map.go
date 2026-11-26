// Package filterhash maps scripts to the integer range used by compact
// block filters.
package filterhash

import (
	"math/bits"

	"github.com/aead/siphash"
)

// MapToRange applies SipHash-2-4 and writes the high 64 bits of each hash
// multiplied by modulus. The results follow the order of scripts, and dst
// must have space for one result per script.
func MapToRange(dst []uint64, key [16]byte, modulus uint64, scripts [][]byte) {
	mapToRange(dst[:len(scripts)], &key, modulus, scripts)
}

func mapScalar(dst []uint64, key *[16]byte, modulus uint64, scripts [][]byte) {
	for i, script := range scripts {
		dst[i], _ = bits.Mul64(siphash.Sum64(script, key), modulus)
	}
}
