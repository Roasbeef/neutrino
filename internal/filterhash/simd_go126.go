//go:build goexperiment.simd && amd64 && !go1.27 && !purego

package filterhash

import "simd/archsimd"

func loadVector(words *[lanes]uint64) archsimd.Uint64x8 {
	return archsimd.LoadUint64x8(words)
}

func storeVector(v archsimd.Uint64x8, words *[lanes]uint64) {
	v.Store(words)
}
