package stagedfilters

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/aead/siphash"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestPrefixCommitmentVector(t *testing.T) {
	t.Parallel()

	stage := wire.MsgCFStage{
		BlockHash: chainhash.Hash{0xff}, N: 253, Data: []byte{0x80, 0x00},
	}
	digest := PrefixCommitment(&stage, chainhash.Hash{0x01, 0x02})
	require.Equal(t, "e5c4b22cc116dde13fe946962662e660f8366c13daff25db0c5ff75af4372ca7",
		hex.EncodeToString(digest[:]))
}

func TestStagedFilterMatchesBIP158(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(29))
	for _, size := range []int{0, 1, 2, 17, 128, 253, 302} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var hash chainhash.Hash
			_, err := rng.Read(hash[:])
			require.NoError(t, err)
			key := builder.DeriveKey(&hash)
			scripts := make([][]byte, size)
			values := make([]uint64, len(scripts))
			for i := range scripts {
				scripts[i] = make([]byte, i%33+1)
				_, err := rng.Read(scripts[i])
				require.NoError(t, err)
				values[i], _ = bits.Mul64(
					siphash.Sum64(scripts[i], &key), uint64(size)*784931,
				)
			}
			slices.Sort(values)
			basic, err := gcs.BuildGCSFilter(19, 784931, key, scripts)
			require.NoError(t, err)
			want, err := basic.NBytes()
			require.NoError(t, err)

			var staged Filter
			for stage, data := range referenceStages(values) {
				require.NoError(t, staged.Add(&wire.MsgCFStage{
					BlockHash: hash, N: uint32(size), Stage: uint8(stage), Data: data,
				}))
				if size != 0 {
					require.True(t, staged.Matches(hash, scripts[:1]))
				}
			}
			got, err := staged.Basic()
			require.NoError(t, err)
			require.Equal(t, want, got)

			for i := range 50 {
				watch := [][]byte{[]byte(fmt.Sprint("watch", i))}
				hit, err := basic.MatchAny(key, watch)
				require.NoError(t, err)
				require.Equal(t, hit, staged.Matches(hash, watch))
			}
		})
	}
}

// referenceStages uses strings as bit arrays independently of the decoder.
func referenceStages(values []uint64) [4][]byte {
	var stages [4]strings.Builder
	var last uint64
	for _, value := range values {
		prefix := value / 4096
		delta := prefix - last
		stages[0].WriteString(strings.Repeat("1", int(delta/128)))
		fmt.Fprintf(&stages[0], "0%07b", delta%128)
		last = prefix
		for i, place := range []uint64{256, 16, 1} {
			fmt.Fprintf(&stages[i+1], "%04b", value/place%16)
		}
	}
	var encoded [4][]byte
	for stage, data := range stages {
		encoded[stage] = make([]byte, (data.Len()+7)/8)
		for i, bit := range data.String() {
			if bit == '1' {
				encoded[stage][i/8] |= 128 >> (i % 8)
			}
		}
	}
	return encoded
}

func TestStagedFilterRejectsMalformedData(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prefix  *wire.MsgCFStage
		invalid wire.MsgCFStage
	}{
		{name: "stage out of order", invalid: wire.MsgCFStage{Stage: 1}},
		{name: "oversized N", invalid: wire.MsgCFStage{N: wire.MaxCFStageElements + 1}},
		{name: "prefix truncation", invalid: wire.MsgCFStage{N: 1}},
		{name: "prefix trailing data", invalid: wire.MsgCFStage{Data: []byte{0}}},
		{name: "prefix over range", invalid: wire.MsgCFStage{N: 1, Data: []byte{0xff}}},
		{name: "prefix nonzero padding", invalid: wire.MsgCFStage{N: 1, Data: []byte{0x80, 0x01}}},
		{
			name: "changed count", prefix: &wire.MsgCFStage{N: 1, Data: []byte{0}},
			invalid: wire.MsgCFStage{Stage: 1, N: 2, Data: []byte{0}},
		},
		{
			name: "trailing refinement bytes", prefix: &wire.MsgCFStage{N: 1, Data: []byte{0}},
			invalid: wire.MsgCFStage{Stage: 1, N: 1, Data: []byte{0, 0}},
		},
		{
			name: "refinement padding", prefix: &wire.MsgCFStage{N: 1, Data: []byte{0}},
			invalid: wire.MsgCFStage{Stage: 1, N: 1, Data: []byte{0x01}},
		},
		{
			name: "reordered equal prefixes", prefix: &wire.MsgCFStage{N: 2, Data: []byte{0, 0}},
			invalid: wire.MsgCFStage{Stage: 1, N: 2, Data: []byte{0xf0}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var filter Filter
			if tc.prefix != nil {
				require.NoError(t, filter.Add(tc.prefix))
			}
			require.Error(t, filter.Add(&tc.invalid))
			_, err := filter.Basic()
			require.Error(t, err)
		})
	}
}
