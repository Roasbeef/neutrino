// Package stagedfilters decodes the experimental four-stage representation of
// a BIP158 basic filter. Callers must authenticate stage data before using it
// to rule out a match.
package stagedfilters

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/neutrino/internal/filterhash"
)

const (
	prefixP    = 7
	prefixDrop = 12
	digitBits  = 4
)

// Filter assembles the ordered stages of one block's filter. Its zero value
// is ready to accept stage zero. Discard the filter if Add fails.
type Filter struct {
	values []uint64
	next   uint8
}

// Add decodes the next stage and retains each increasingly precise value.
func (f *Filter) Add(m *wire.MsgCFStage) error {
	if m.Stage != f.next || m.Stage > wire.MaxCFStage {
		return fmt.Errorf("unexpected filter stage %d", m.Stage)
	}
	if m.N > wire.MaxCFStageElements || len(m.Data) > wire.MaxCFStageDataSize {
		return errors.New("filter stage exceeds profile limits")
	}

	var maximum uint64
	if m.N != 0 {
		maximum = (uint64(m.N)*builder.DefaultM - 1) >> remaining(m.Stage)
	}
	var err error
	if m.Stage == 0 {
		f.values, err = decodePrefixes(m.N, m.Data, maximum)
	} else {
		if int(m.N) != len(f.values) {
			return errors.New("filter stage count changed")
		}
		err = refine(f.values, m.Data, maximum)
	}
	if err != nil {
		return err
	}
	f.next++
	return nil
}

// Matches compares scripts to all values disclosed so far. A stage zero miss
// applies to the full filter only if the stage was authenticated separately.
func (f *Filter) Matches(hash chainhash.Hash, scripts [][]byte) bool {
	if len(f.values) == 0 || len(scripts) == 0 {
		return false
	}

	var small [16]uint64
	targets := small[:]
	if len(scripts) > len(targets) {
		targets = make([]uint64, len(scripts))
	}
	targets = targets[:len(scripts)]
	filterhash.MapToRange(
		targets, builder.DeriveKey(&hash),
		uint64(len(f.values))*builder.DefaultM, scripts,
	)
	shift := remaining(f.next - 1)
	for _, target := range targets {
		if _, found := slices.BinarySearch(f.values, target>>shift); found {
			return true
		}
	}
	return false
}

// Basic serializes the complete filter as canonical BIP158 bytes, including
// its CompactSize element count.
func (f *Filter) Basic() ([]byte, error) {
	if f.next != wire.MaxCFStage+1 {
		return nil, errors.New("incomplete staged filter")
	}

	var count bytes.Buffer
	if err := wire.WriteVarInt(&count, 0, uint64(len(f.values))); err != nil {
		return nil, err
	}
	var last uint64
	bitLen := len(f.values) * (builder.DefaultP + 1)
	for _, value := range f.values {
		bitLen += int((value - last) >> builder.DefaultP)
		last = value
	}
	size := count.Len() + (bitLen+7)/8
	if size > wire.MaxCFilterDataSize {
		return nil, errors.New("reconstructed basic filter is too large")
	}
	basic := make([]byte, size)
	copy(basic, count.Bytes())

	var cursor int
	last = 0
	payload := basic[count.Len():]
	for _, value := range f.values {
		delta := value - last
		last = value
		for quotient := delta >> builder.DefaultP; quotient > 0; quotient-- {
			writeBits(payload, &cursor, 1, 1)
		}
		cursor++ // The terminating zero is already set.
		writeBits(payload, &cursor, delta, builder.DefaultP)
	}
	return basic, nil
}

// PrefixCommitment binds the exact stage-zero payload and its element count
// to the block and the independently authenticated BIP158 filter hash.
func PrefixCommitment(m *wire.MsgCFStage, basicHash chainhash.Hash) chainhash.Hash {
	const domain = "cfilter-stage0/v1\x00"
	var input bytes.Buffer
	input.Grow(len(domain) + 2*chainhash.HashSize +
		wire.VarIntSerializeSize(uint64(m.N)) + len(m.Data))
	input.WriteString(domain)
	input.Write(m.BlockHash[:])
	input.Write(basicHash[:])
	_ = wire.WriteVarInt(&input, 0, uint64(m.N))
	input.Write(m.Data)
	return chainhash.DoubleHashH(input.Bytes())
}

func remaining(stage uint8) uint8 {
	return prefixDrop - digitBits*stage
}

func decodePrefixes(n uint32, data []byte, maximum uint64) ([]uint64, error) {
	// Each prefix uses at least eight bits. Check before allocating.
	if len(data) < int(n) {
		return nil, errors.New("truncated filter prefix")
	}
	values := make([]uint64, n)
	var cursor int
	var last uint64
	for i := range values {
		var quotient uint64
		for {
			bit, err := readBits(data, &cursor, 1)
			if err != nil {
				return nil, err
			}
			if bit == 0 {
				break
			}
			quotient++
			if quotient > (maximum-last)>>prefixP {
				return nil, errors.New("filter prefix outside basic filter range")
			}
		}
		remainder, err := readBits(data, &cursor, prefixP)
		if err != nil {
			return nil, err
		}
		last += quotient<<prefixP | remainder
		if last > maximum {
			return nil, errors.New("filter prefix outside basic filter range")
		}
		values[i] = last
	}
	if len(data)*8-cursor >= 8 {
		return nil, errors.New("trailing bytes in filter prefix")
	}
	if pad := len(data)*8 - cursor; pad != 0 &&
		data[len(data)-1]&byte((1<<pad)-1) != 0 {

		return nil, errors.New("nonzero filter prefix padding")
	}
	return values, nil
}

func refine(values []uint64, data []byte, maximum uint64) error {
	if len(data) != (len(values)+1)/2 {
		return errors.New("wrong filter refinement length")
	}
	if len(values)%2 != 0 && data[len(data)-1]&0x0f != 0 {
		return errors.New("nonzero filter refinement padding")
	}
	var last uint64
	for i, prefix := range values {
		digit := (data[i/2] >> (digitBits * (1 - i%2))) & 0x0f
		value := prefix<<digitBits | uint64(digit)
		if value < last || value > maximum {
			return errors.New("invalid filter refinement value")
		}
		values[i] = value
		last = value
	}
	return nil
}

func readBits(data []byte, cursor *int, width int) (uint64, error) {
	if len(data)*8-*cursor < width {
		return 0, errors.New("truncated filter prefix")
	}
	var value uint64
	for width != 0 {
		space := 8 - *cursor%8
		step := min(width, space)
		mask := byte((1 << step) - 1)
		value = value<<step |
			uint64((data[*cursor/8]>>(space-step))&mask)
		*cursor += step
		width -= step
	}
	return value, nil
}

func writeBits(data []byte, cursor *int, value uint64, width int) {
	for width != 0 {
		space := 8 - *cursor%8
		step := min(width, space)
		mask := uint64((1 << step) - 1)
		data[*cursor/8] |= byte((value>>(width-step))&mask) << (space - step)
		*cursor += step
		width -= step
	}
}
