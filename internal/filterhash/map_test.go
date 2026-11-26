package filterhash

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

func TestMapToRange(t *testing.T) {
	rng := rand.New(rand.NewPCG(168, 158))
	var key [16]byte
	for i := range key {
		key[i] = byte(rng.Uint64())
	}

	moduli := []uint64{0, 1, 784931, 784931 * 30_000, ^uint64(0)}
	for length := range 67 {
		for _, count := range []int{0, 1, 7, 8, 15, 16, 17, 32, 97} {
			scripts := makeScripts(rng, count, []int{length})
			if count > 1 {
				scripts[count-1] = scripts[0]
			}
			for _, modulus := range moduli {
				checkRange(t, scripts, key, modulus)
			}
		}
	}

	scripts := makeScripts(rng, 11, []int{22, 23, 25, 34, 72})
	scripts = append(scripts, makeScripts(rng, 17, []int{34})...)
	scripts = append(scripts, nil, []byte{0}, make([]byte, 260))
	scripts = append(scripts, makeScripts(rng, 20, []int{22})...)
	for _, modulus := range moduli {
		checkRange(t, scripts, key, modulus)
	}
}

func checkRange(t *testing.T, scripts [][]byte, key [16]byte, modulus uint64) {
	t.Helper()
	want := make([]uint64, len(scripts))
	got := make([]uint64, len(scripts)+1)
	got[len(scripts)] = 456
	mapScalar(want, &key, modulus, scripts)
	MapToRange(got, key, modulus, scripts)
	if !slices.Equal(got[:len(scripts)], want) || got[len(scripts)] != 456 {
		t.Fatalf("maps differ for %d scripts with modulus %d\ngot  %x\nwant %x",
			len(scripts), modulus, got, want)
	}
}

func makeScripts(rng *rand.Rand, count int, lengths []int) [][]byte {
	scripts := make([][]byte, count)
	for i := range scripts {
		script := make([]byte, lengths[i%len(lengths)])
		for j := range script {
			script[j] = byte(rng.Uint64())
		}
		scripts[i] = script
	}
	return scripts
}

func BenchmarkMapToRange(b *testing.B) {
	const modulus = 784931 * 8_000
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8}
	rng := rand.New(rand.NewPCG(168, 158))
	grouped := make([]int, 0, 96)
	for _, length := range []int{22, 23, 25, 34} {
		for range 24 {
			grouped = append(grouped, length)
		}
	}
	for _, shape := range []struct {
		name    string
		lengths []int
	}{
		{"p2wpkh", []int{22}},
		{"p2tr", []int{34}},
		{"mixed", []int{22, 23, 25, 34}},
		{"grouped", grouped},
	} {
		for _, count := range []int{1, 8, 16, 32, 128, 512} {
			scripts := makeScripts(rng, count, shape.lengths)
			dst := make([]uint64, len(scripts))
			b.Run(fmt.Sprintf("%s/%d/scalar", shape.name, count), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					mapScalar(dst, &key, modulus, scripts)
				}
			})
			b.Run(fmt.Sprintf("%s/%d/selected", shape.name, count), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					MapToRange(dst, key, modulus, scripts)
				}
			})
		}
	}
}
