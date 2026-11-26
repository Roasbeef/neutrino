package neutrino

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/lightninglabs/neutrino/filtermatch"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/lightninglabs/neutrino/internal/filterhash"
	"github.com/lightninglabs/neutrino/internal/stagedfilters"
	"github.com/stretchr/testify/require"
)

func TestStagedFiltersOnBitcoinPeer(t *testing.T) {
	for _, test := range []struct {
		name       string
		commitment bool
		watchHit   bool
		altered    bool
		vanilla    bool
		want       []string
	}{
		{
			name:       "authenticated prefix miss",
			commitment: true,
			want:       []string{"getcfstages:0:3"},
		},
		{
			name:       "authenticated prefix pruning",
			commitment: true,
			watchHit:   true,
			want: []string{
				"getcfstages:0:3", "getcfstage:1:1",
				"getcfstage:2:1", "getcfstage:3:1",
			},
		},
		{
			name:     "authenticate using all stages",
			watchHit: true,
			want: []string{
				"getcfstages:0:3", "getcfstages:1:3",
				"getcfstages:2:3", "getcfstages:3:3",
			},
		},
		{
			name:       "altered prefix falls back to BIP157",
			commitment: true,
			watchHit:   true,
			altered:    true,
			want: []string{
				"getcfstages:0:3", "getcfstage:1:1", "getcfstage:2:1",
				"getcfstage:3:1", "getcfilters",
			},
		},
		{
			name:     "vanilla peer falls back to BIP157",
			watchHit: true,
			vanilla:  true,
			want:     []string{"getcfstages:0:3", "getcfilters"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := chaincfg.SimNetParams
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })

			addr := listener.Addr().String()
			cfg := &StagedFilterConfig{Peer: addr, Timeout: time.Second}
			if test.vanilla {
				cfg.Timeout = 100 * time.Millisecond
			}
			fixtures := make(map[chainhash.Hash]stagedFixture)
			if test.commitment {
				cfg.Stage0Commitment = func(hash chainhash.Hash) (
					chainhash.Hash, chainhash.Hash, bool) {

					f, ok := fixtures[hash]
					return f.basicHash, f.prefixDigest, ok
				}
			}
			dataDir := t.TempDir()
			db, err := walletdb.Create("bdb", filepath.Join(dataDir, "neutrino.db"),
				true, dbOpenTimeout, false)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })

			svc, err := NewChainService(Config{
				DataDir: dataDir, Database: db, ChainParams: params,
				ConnectPeers: []string{addr}, StagedFilters: cfg,
			})
			require.NoError(t, err)
			watchScript := []byte{0x51}
			blocks := seedStagedFixtures(t, svc, watchScript, fixtures)
			hashes := make([]chainhash.Hash, len(blocks))
			for i, block := range blocks {
				hashes[i] = *block.Hash()
			}
			requests := make(chan string, 10)
			go serveStagedFixtures(listener, hashes, fixtures, requests,
				test.vanilla, test.altered)
			require.NoError(t, svc.Start(t.Context()))
			t.Cleanup(func() { require.NoError(t, svc.Stop()) })
			waitForPeer(t, svc, addr)

			watch := [][]byte{watchScript}
			if !test.watchHit {
				watch = [][]byte{{0x52}}
			}
			matcher := (&RescanChainSource{svc}).BlockMatcher()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			fetches := 0
			getBlock := func(_ context.Context, hash chainhash.Hash) (
				*btcutil.Block, error) {

				fetches++
				require.Equal(t, hashes[0], hash)
				return blocks[0], nil
			}
			got, err := filtermatch.FetchMatchingBlock(
				ctx, matcher, hashes[0], watch, true, getBlock,
			)
			require.NoError(t, err)
			if test.watchHit {
				require.Same(t, blocks[0], got)
				require.Equal(t, 1, fetches)
			} else {
				require.Nil(t, got)
				require.Zero(t, fetches)
			}

			// The adjacent miss was prefetched on the same connection.
			got, err = filtermatch.FetchMatchingBlock(
				ctx, matcher, hashes[1], watch, true, getBlock,
			)
			require.NoError(t, err)
			require.Nil(t, got)
			var observed []string
			for len(requests) > 0 {
				observed = append(observed, <-requests)
			}
			require.Equal(t, test.want, observed)

			if !test.watchHit {
				// A cached prefix is matched again for a watch list
				// that changed after the historical query.
				got, err = filtermatch.FetchMatchingBlock(
					ctx, matcher, hashes[0], [][]byte{watchScript}, true,
					getBlock,
				)
				require.NoError(t, err)
				require.Same(t, blocks[0], got)
				require.Len(t, requests, 4)
				for stage := range 4 {
					require.Equal(t, fmt.Sprintf("getcfstage:%d:1", stage),
						<-requests)
				}
			}
		})
	}
}

type stagedFixture struct {
	stages       [4]wire.MsgCFStage
	basic        []byte
	basicHash    chainhash.Hash
	prefixDigest chainhash.Hash
}

func seedStagedFixtures(t *testing.T, svc *ChainService, script []byte,
	fixtures map[chainhash.Hash]stagedFixture) []*btcutil.Block {

	t.Helper()
	prev := svc.chainParams.GenesisBlock.Header
	prevFilter, _, err := svc.RegFilterHeaders.ChainTip()
	require.NoError(t, err)
	var blocks []*btcutil.Block
	var blockHeaders []headerfs.BlockHeader
	var filterHeaders []headerfs.FilterHeader
	for height := uint32(1); height <= 3; height++ {
		header := wire.BlockHeader{
			Version: prev.Version, PrevBlock: prev.BlockHash(),
			Timestamp: prev.Timestamp.Add(time.Minute),
			Bits:      prev.Bits, Nonce: height,
		}
		block := wire.NewMsgBlock(&header)
		if height == 1 {
			tx := wire.NewMsgTx(2)
			tx.AddTxOut(wire.NewTxOut(1000, script))
			require.NoError(t, block.AddTransaction(tx))
		}
		blocks = append(blocks, btcutil.NewBlock(block))
		basicFilter, err := builder.BuildBasicFilter(block, nil)
		require.NoError(t, err)
		basicBytes, err := basicFilter.NBytes()
		require.NoError(t, err)
		hash := header.BlockHash()
		fixture := stagedFixture{
			basic: basicBytes, basicHash: chainhash.DoubleHashH(basicBytes),
		}
		for i := range fixture.stages {
			fixture.stages[i] = wire.MsgCFStage{Stage: uint8(i), BlockHash: hash}
		}
		if height == 1 {
			// This fixture contains exactly one mapped value. Its
			// prefix Rice quotient is either zero or one.
			var value [1]uint64
			filterhash.MapToRange(
				value[:], builder.DeriveKey(&hash), builder.DefaultM,
				[][]byte{script},
			)
			prefix := byte(value[0] >> 12)
			if prefix < 128 {
				fixture.stages[0].Data = []byte{prefix}
			} else {
				r := prefix - 128
				fixture.stages[0].Data = []byte{0x80 | r>>1, r << 7}
			}
			for i := range fixture.stages {
				fixture.stages[i].N = 1
				if i != 0 {
					digit := byte(value[0]>>((3-i)*4)) & 0x0f
					fixture.stages[i].Data = []byte{digit << 4}
				}
			}
		}
		fixture.prefixDigest = stagedfilters.PrefixCommitment(
			&fixture.stages[0], fixture.basicHash,
		)
		fixtures[hash] = fixture

		filterHeader, err := builder.MakeHeaderForFilter(basicFilter, *prevFilter)
		require.NoError(t, err)
		filterHeaders = append(filterHeaders, headerfs.FilterHeader{
			HeaderHash: hash, FilterHash: filterHeader, Height: height,
		})
		blockHeaders = append(blockHeaders, headerfs.BlockHeader{
			BlockHeader: &header, Height: height,
		})
		prev, prevFilter = header, &filterHeader
	}
	require.NoError(t, svc.BlockHeaders.WriteHeaders(blockHeaders...))
	require.NoError(t, svc.RegFilterHeaders.WriteHeaders(filterHeaders...))
	require.NoError(t, svc.blockManager.ResetHeaderState())
	return blocks
}

func serveStagedFixtures(listener net.Listener, hashes []chainhash.Hash,
	fixtures map[chainhash.Hash]stagedFixture, requests chan<- string,
	vanilla, altered bool) {

	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	pver := wire.AddrV2Version
	network := chaincfg.SimNetParams.Net
	write := func(msg wire.Message) error {
		return wire.WriteMessage(conn, msg, pver, network)
	}
	if _, _, err := wire.ReadMessage(conn, pver, network); err != nil {
		return
	}
	services := wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeCF
	me := wire.NewNetAddressIPPort(net.IPv4(127, 0, 0, 1), 18555, services)
	version := wire.NewMsgVersion(me, me, 7, int32(len(hashes)))
	version.Services = services
	version.ProtocolVersion = int32(pver)
	if write(version) != nil || write(wire.NewMsgVerAck()) != nil {
		return
	}
	respond := func(req wire.Message, stage uint8, requested []chainhash.Hash) error {
		requests <- fmt.Sprintf("%s:%d:%d", req.Command(), stage, len(requested))
		if vanilla {
			return nil
		}
		for _, hash := range requested {
			m := fixtures[hash].stages[stage]
			if altered && hash == hashes[0] {
				m.N, m.Data = 0, nil
			}
			if err := write(&m); err != nil {
				return err
			}
		}
		return nil
	}
	for {
		msg, _, err := wire.ReadMessage(conn, pver, network)
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *wire.MsgGetHeaders:
			err = write(wire.NewMsgHeaders())
		case *wire.MsgPing:
			err = write(wire.NewMsgPong(m.Nonce))
		case *wire.MsgGetCFCheckpt:
			err = write(wire.NewMsgCFCheckpt(m.FilterType, &m.StopHash, 0))
		case *wire.MsgGetCFStage:
			err = respond(m, m.Stage, []chainhash.Hash{m.BlockHash})
		case *wire.MsgGetCFStages:
			err = respond(m, m.Stage, m.BlockHashes)
		case *wire.MsgGetCFilters:
			requests <- m.Command()
			for _, hash := range hashes[m.StartHeight-1:] {
				err = write(wire.NewMsgCFilter(m.FilterType, &hash, fixtures[hash].basic))
				if err != nil || hash == m.StopHash {
					break
				}
			}
		}
		if err != nil {
			return
		}
	}
}
