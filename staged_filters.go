package neutrino

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/neutrino/filterdb"
	"github.com/lightninglabs/neutrino/filtermatch"
	"github.com/lightninglabs/neutrino/internal/stagedfilters"
	querysyncwm "github.com/lightninglabs/neutrino/querysync/workmanager"
)

const stagedFilterTimeout = 2 * time.Second

// StagedFilterConfig enables experimental staged compact filter queries for
// rescans and GetUtxo on regtest or simnet.
type StagedFilterConfig struct {
	// Peer is the address of a normal connected peer explicitly configured
	// to serve stages. Set ConnectPeers or AddPeers to connect to this node.
	Peer string

	// Timeout covers all the stage requests for one lookup. A zero timeout
	// uses two seconds. A timeout falls back to regular compact filters.
	Timeout time.Duration

	// Stage0Commitment optionally supplies an independently trusted basic
	// filter hash and stage-zero digest for a block. The digest is SHA256d
	// of "cfilter-stage0/v1\x00", raw block hash, raw basic filter hash,
	// CompactSize element count, and the exact stage-zero payload. The
	// authority must have accurately derived the prefix from that filter.
	// The client checks the basic hash against its regular filter headers.
	// Without this callback or a matching commitment, a negative requires
	// the complete reconstructed filter. The callback must return promptly.
	Stage0Commitment func(block chainhash.Hash) (basicHash, digest chainhash.Hash,
		ok bool)
}

type stagedFilterSource struct {
	service *ChainService
	config  StagedFilterConfig
	peer    peerKey
	basic   filtermatch.BasicFilterSource

	// One in-flight staged batch owns the connection's request stream and
	// the recent authenticated prefixes. Concurrent matches use BIP158.
	active   chan struct{}
	prefixes map[chainhash.Hash]*stagedFilterEntry
}

type stagedFilterEntry struct {
	hash          chainhash.Hash
	height        uint32
	previous      chainhash.Hash
	header        chainhash.Hash
	filter        stagedfilters.Filter
	prefixDigest  chainhash.Hash
	prefixSkipped bool
	basic         *gcs.Filter
}

func newStagedFilterSource(s *ChainService, c StagedFilterConfig) (
	*stagedFilterSource, error) {

	if !isDevNetwork(s.chainParams.Net) {
		return nil, errors.New("staged compact filters require regtest or simnet")
	}
	if c.Peer == "" {
		return nil, errors.New("staged compact filters require a peer address")
	}
	if c.Timeout < 0 {
		return nil, errors.New("staged compact filter timeout must be nonnegative")
	}
	if c.Timeout == 0 {
		c.Timeout = stagedFilterTimeout
	}
	addr, err := s.addrStringToNetAddr(c.Peer)
	if err != nil {
		return nil, fmt.Errorf("resolving staged compact filter peer: %w", err)
	}
	return &stagedFilterSource{
		service: s,
		config:  c,
		peer:    keyOf(addr),
		basic:   basicFilterSource(s.GetCFilter),
		active:  make(chan struct{}, 1),
	}, nil
}

func (s *stagedFilterSource) Match(ctx context.Context, hash chainhash.Hash,
	scripts [][]byte, batch bool) (filtermatch.Decision[*gcs.Filter], error) {

	var unknown filtermatch.Decision[*gcs.Filter]
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	filter, err := s.service.fetchStoredFilter(hash, filterdb.RegularFilter)
	if err != nil {
		return unknown, err
	}
	if filter != nil {
		stored := filtermatch.BasicFilterSource(func(context.Context,
			chainhash.Hash, bool) (*gcs.Filter, error) {

			return filter, nil
		})
		return stored.Match(ctx, hash, scripts, batch)
	}

	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	default:
		return s.basic.Match(ctx, hash, scripts, batch)
	}

	stagedBatch := batch
	if entry := s.prefixes[hash]; entry != nil && s.prefixStillTrusted(entry) {

		if !entry.filter.Matches(hash, scripts) {
			return filtermatch.Skip[*gcs.Filter](), nil
		}
		// A changed watch list can make a prefetched prefix a candidate.
		// Other blocks in the same range have already been prefetched.
		stagedBatch = false
	}

	queryCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	entry, err := s.fetch(queryCtx, hash, scripts, stagedBatch)
	cancel()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return unknown, ctxErr
	}
	if errors.Is(err, ErrShuttingDown) {
		return unknown, err
	}
	if err != nil {
		log.Debugf("Staged compact filter lookup for %v: %v", hash, err)
		return s.basic.Match(ctx, hash, scripts, batch)
	}
	if entry.prefixSkipped || !entry.filter.Matches(hash, scripts) {
		return filtermatch.Skip[*gcs.Filter](), nil
	}
	return filtermatch.Candidate(entry.basic), nil
}

func (s *stagedFilterSource) Verify(filter *gcs.Filter, block *btcutil.Block) error {
	return s.basic.Verify(filter, block)
}

func (s *stagedFilterSource) fetch(ctx context.Context, hash chainhash.Hash,
	scripts [][]byte, batch bool) (*stagedFilterEntry, error) {

	if hash == *s.service.chainParams.GenesisHash {
		return nil, errors.New("genesis filter is stored locally")
	}
	p, err := s.connectedPeer(ctx)
	if err != nil {
		return nil, err
	}
	batchType := noBatch
	if batch {
		batchType = forwardBatch
	}
	q, err := s.service.prepareCFiltersQuery(
		hash, wire.GCSFilterRegular, batchType, wire.MaxGetCFStagesHashes,
	)
	if err != nil {
		return nil, err
	}
	targetIndex, exists := q.headerIndex[hash]
	if !exists {
		return nil, errors.New("target block left the filter header chain")
	}
	entries := make([]*stagedFilterEntry, len(q.headerIndex))
	for h, i := range q.headerIndex {
		entries[i-1] = &stagedFilterEntry{
			hash:     h,
			height:   uint32(q.startHeight) + uint32(i) - 1,
			previous: q.filterHeaders[i-1],
			header:   q.filterHeaders[i],
		}
	}
	if err := s.fetchStages(ctx, p, entries, scripts); err != nil {
		return nil, err
	}
	// The anchor covers the complete contiguous range. Recheck it after
	// the network exchange before retaining or matching any result.
	if !s.service.stagedFilterOnChain(entries[len(entries)-1]) {
		return nil, errors.New("staged compact filter chain changed during lookup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if batch {
		s.prefixes = make(map[chainhash.Hash]*stagedFilterEntry, len(entries))
	}
	for _, e := range entries {
		if e.prefixSkipped {
			if batch {
				s.prefixes[e.hash] = e
			}
			continue
		}
		if _, err := s.service.putFilterToCache(
			&e.hash, filterdb.RegularFilter, e.basic,
		); err != nil {
			log.Warnf("Couldn't cache staged compact filter: %v", err)
		}
	}

	return entries[targetIndex-1], nil
}

func (s *stagedFilterSource) connectedPeer(ctx context.Context) (
	*ServerPeer, error) {

	// The buffered reply lets the peer handler finish if this request is
	// canceled after it receives the query.
	reply := make(chan []*ServerPeer, 1)
	select {
	case s.service.query <- getPeersMsg{reply: reply}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.service.quit:
		return nil, ErrShuttingDown
	}
	select {
	case peers := <-reply:
		for _, p := range peers {
			if p.key() == s.peer {
				return p, nil
			}
		}
		return nil, errors.New("configured staged compact filter peer unavailable")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.service.quit:
		return nil, ErrShuttingDown
	}
}

func (s *stagedFilterSource) fetchStages(ctx context.Context,
	peer querysyncwm.Peer, entries []*stagedFilterEntry, scripts [][]byte) error {

	messages, unsubscribe := peer.SubscribeRecvMsg()
	defer unsubscribe()

	for stage := uint8(0); stage <= wire.MaxCFStage; stage++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		hashes := make([]chainhash.Hash, 0, len(entries))
		pending := make(map[chainhash.Hash]*stagedFilterEntry, len(entries))
		for _, e := range entries {
			if !e.prefixSkipped {
				hashes = append(hashes, e.hash)
				pending[e.hash] = e
			}
		}
		if len(hashes) == 0 {
			return nil
		}

		var req wire.Message = wire.NewMsgGetCFStage(&hashes[0], stage)
		if len(hashes) > 1 {
			req = wire.NewMsgGetCFStages(hashes, stage)
		}
		peer.QueueMessageWithEncoding(req, nil, wire.LatestEncoding)
		for len(pending) > 0 {
			select {
			case message, ok := <-messages:
				if !ok {
					return querysyncwm.ErrPeerDisconnected
				}
				m, ok := message.(*wire.MsgCFStage)
				if !ok || m.Stage != stage {
					continue
				}
				e := pending[m.BlockHash]
				if e == nil {
					continue
				}
				if err := s.applyStage(e, m, scripts); err != nil {
					return err
				}
				delete(pending, m.BlockHash)
			case <-ctx.Done():
				return ctx.Err()
			case <-peer.OnDisconnect():
				return querysyncwm.ErrPeerDisconnected
			case <-s.service.quit:
				return ErrShuttingDown
			}
		}
	}
	return nil
}

func (s *stagedFilterSource) applyStage(entry *stagedFilterEntry,
	m *wire.MsgCFStage, scripts [][]byte) error {

	if err := entry.filter.Add(m); err != nil {
		return fmt.Errorf("decoding staged filter for %v: %w", entry.hash, err)
	}
	switch m.Stage {
	case 0:
		if lookup := s.config.Stage0Commitment; lookup != nil {
			basicHash, digest, ok := lookup(entry.hash)
			if ok && matchesFilterHeader(basicHash, entry) &&
				stagedfilters.PrefixCommitment(m, basicHash) == digest {

				entry.prefixDigest = digest
				entry.prefixSkipped = !entry.filter.Matches(entry.hash, scripts)
			}
		}

	case wire.MaxCFStage:
		enc, err := entry.filter.Basic()
		if err != nil {
			return err
		}
		if !matchesFilterHeader(chainhash.DoubleHashH(enc), entry) {
			return fmt.Errorf("staged filter for %v failed basic filter header check",
				entry.hash)
		}
		entry.basic, err = gcs.FromNBytes(builder.DefaultP, builder.DefaultM, enc)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *stagedFilterSource) prefixStillTrusted(e *stagedFilterEntry) bool {
	basicHash, digest, ok := s.config.Stage0Commitment(e.hash)
	return ok && digest == e.prefixDigest && matchesFilterHeader(basicHash, e) &&
		s.service.stagedFilterOnChain(e)
}

func matchesFilterHeader(filterHash chainhash.Hash, entry *stagedFilterEntry) bool {
	var headers [2 * chainhash.HashSize]byte
	copy(headers[:chainhash.HashSize], filterHash[:])
	copy(headers[chainhash.HashSize:], entry.previous[:])
	return chainhash.DoubleHashH(headers[:]) == entry.header
}

func (s *ChainService) stagedFilterOnChain(e *stagedFilterEntry) bool {
	blockHash, err := s.GetBlockHash(int64(e.height))
	if err != nil || *blockHash != e.hash {
		return false
	}
	filterHeader, err := s.RegFilterHeaders.FetchHeaderByHeight(e.height)
	return err == nil && *filterHeader == e.header
}
