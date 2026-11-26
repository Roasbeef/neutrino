//go:build !goexperiment.simd || !amd64 || purego

package filterhash

func mapToRange(dst []uint64, key *[16]byte, modulus uint64, scripts [][]byte) {
	mapScalar(dst, key, modulus, scripts)
}
