package headerfs

import (
	"bytes"
	"crypto/sha256"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/davecgh/go-spew/spew"
)

func createTestBlockHeaderStore() (func(), walletdb.DB, string, *BlockHeaderStore, error) {
	tempDir, err := ioutil.TempDir("", "store_test")
	if err != nil {
		return nil, nil, "", nil, err
	}

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return nil, nil, "", nil, err
	}

	hStore, err := NewBlockHeaderStore(tempDir, db, &chaincfg.SimNetParams)
	if err != nil {
		return nil, nil, "", nil, err
	}

	cleanUp := func() {
		os.RemoveAll(tempDir)
		db.Close()
	}

	return cleanUp, db, tempDir, hStore, nil
}

func createTestBlockHeaderChain(numHeaders uint32) []*BlockHeader {
	blockHeaders := make([]*BlockHeader, numHeaders)
	prevHeader := &chaincfg.SimNetParams.GenesisBlock.Header
	for i := uint32(1); i <= numHeaders; i++ {
		bitcoinHeader := &wire.BlockHeader{
			Bits:      uint32(rand.Int31()),
			Nonce:     uint32(rand.Int31()),
			Timestamp: prevHeader.Timestamp.Add(time.Minute * 1),
			PrevBlock: prevHeader.BlockHash(),
		}

		blockHeaders[i-1] = &BlockHeader{
			BlockHeader: bitcoinHeader,
			Height:      i,
		}

		prevHeader = bitcoinHeader
	}

	return blockHeaders
}

func TestBlockHeaderStoreOperations(t *testing.T) {
	cleanUp, _, _, bhs, err := createTestBlockHeaderStore()
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		t.Fatalf("unable to create new block header store: %v", err)
	}

	rand.Seed(time.Now().Unix())

	// With our test instance created, we'll now generate a series of
	// "fake" block headers to insert into the database.
	const numHeaders = 100
	blockHeaders := createTestBlockHeaderChain(numHeaders)

	// With all the headers inserted, we'll now insert them into the
	// database in a single batch.
	if err := bhs.WriteHeaders(blockHeaders...); err != nil {
		t.Fatalf("unable to write block headers: %v", err)
	}

	// At this point, the _tip_ of the chain from the PoV of the database
	// should be the very last header we inserted.
	lastHeader := blockHeaders[len(blockHeaders)-1]
	tipHeader, tipHeight, err := bhs.ChainTip()
	if err != nil {
		t.Fatalf("unable to fetch chain tip")
	}
	if !reflect.DeepEqual(lastHeader.BlockHeader, tipHeader) {
		t.Fatalf("tip height headers don't match up: "+
			"expected %v, got %v", spew.Sdump(lastHeader),
			spew.Sdump(tipHeader))
	}
	if tipHeight != lastHeader.Height {
		t.Fatalf("chain tip doesn't match: expected %v, got %v",
			lastHeader.Height, tipHeight)
	}

	// Ensure that from the PoV of the database, the headers perfectly
	// connect.
	if err := bhs.CheckConnectivity(); err != nil {
		t.Fatalf("bhs detects that headers don't connect: %v", err)
	}

	// With all the headers written, we should be able to retrieve each
	// header according to its hash _and_ height.
	for _, header := range blockHeaders {
		dbHeader, err := bhs.FetchHeaderByHeight(header.Height)
		if err != nil {
			t.Fatalf("unable to fetch header by height: %v", err)
		}
		if !reflect.DeepEqual(*header.BlockHeader, *dbHeader) {
			t.Fatalf("retrieved by height headers don't match up: "+
				"expected %v, got %v", spew.Sdump(*header.BlockHeader),
				spew.Sdump(*dbHeader))
		}

		blockHash := header.BlockHash()
		dbHeader, err = bhs.FetchHeader(&blockHash)
		if err != nil {
			t.Fatalf("unable to fetch header by hash: %v", err)
		}
		if !reflect.DeepEqual(*dbHeader, *header.BlockHeader) {
			t.Fatalf("retrieved by hash headers don't match up: "+
				"expected %v, got %v", spew.Sdump(header),
				spew.Sdump(dbHeader))
		}
	}

	// Finally, we'll test the roll back scenario. Roll back the chain by a
	// single block, the returned block stamp should exactly match the last
	// header inserted, and the current chain tip should be the second to
	// last header inserted.
	secondToLastHeader := blockHeaders[len(blockHeaders)-2]
	blockStamp, err := bhs.RollbackLastBlock()
	if err != nil {
		t.Fatalf("unable to rollback chain: %v", err)
	}
	if lastHeader.Height != uint32(blockStamp.Height) {
		t.Fatalf("chain tip doesn't match: expected %v, got %v",
			lastHeader.Height, blockStamp.Height)
	}
	headerHash := lastHeader.BlockHash()
	if !bytes.Equal(headerHash[:], blockStamp.Hash[:]) {
		t.Fatalf("header hashes don't match: expected %v, got %v",
			headerHash, blockStamp.Hash)
	}
	tipHeader, tipHeight, err = bhs.ChainTip()
	if err != nil {
		t.Fatalf("unable to fetch chain tip")
	}
	if !reflect.DeepEqual(secondToLastHeader.BlockHeader, tipHeader) {
		t.Fatalf("tip height headers don't match up: "+
			"expected %v, got %v", spew.Sdump(secondToLastHeader),
			spew.Sdump(tipHeader))
	}
	if tipHeight != secondToLastHeader.Height {
		t.Fatalf("chain tip doesn't match: expected %v, got %v",
			secondToLastHeader.Height, tipHeight)
	}
}

func TestBlockHeaderStoreRecovery(t *testing.T) {
	// In this test we want to exercise the ability of the block header
	// store to recover in the face of a partial batch write (the headers
	// were written, but the index wasn't updated).
	cleanUp, db, tempDir, bhs, err := createTestBlockHeaderStore()
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		t.Fatalf("unable to create new block header store: %v", err)
	}

	// First we'll generate a test header chain of length 10, inserting it
	// into the header store.
	blockHeaders := createTestBlockHeaderChain(10)
	if err := bhs.WriteHeaders(blockHeaders...); err != nil {
		t.Fatalf("unable to write block headers: %v", err)
	}

	// Next, in order to simulate a partial write, we'll roll back the
	// internal index by 5 blocks.
	for i := 0; i < 5; i++ {
		if err := bhs.truncateIndex(); err != nil {
			t.Fatalf("unable to truncate index: %v", err)
		}
	}

	// Next, we'll re-create the block header store in order to trigger the
	// recovery logic.
	bhs, err = NewBlockHeaderStore(tempDir, db, &chaincfg.SimNetParams)
	if err != nil {
		t.Fatalf("unable to re-create bhs: %v", err)
	}

	// The chain tip of this new instance should be of height 5, and match
	// the 5th to last block header.
	tipHash, tipHeight, err := bhs.ChainTip()
	if err != nil {
		t.Fatalf("unable to get chain tip: %v", err)
	}
	if tipHeight != 5 {
		t.Fatalf("tip height mismatch: expected %v, got %v", 5, tipHeight)
	}
	prevHeaderHash := blockHeaders[5].BlockHash()
	tipBlockHash := tipHash.BlockHash()
	if bytes.Equal(prevHeaderHash[:], tipBlockHash[:]) {
		t.Fatalf("block hash mismatch: expected %v, got %v",
			prevHeaderHash, tipBlockHash)
	}
}

func createTestFilterHeaderStore() (func(), walletdb.DB, string, *FilterHeaderStore, error) {
	tempDir, err := ioutil.TempDir("", "store_test")
	if err != nil {
		return nil, nil, "", nil, err
	}

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return nil, nil, "", nil, err
	}

	hStore, err := NewFilterHeaderStore(tempDir, db, RegularFilter,
		&chaincfg.SimNetParams)
	if err != nil {
		return nil, nil, "", nil, err
	}

	cleanUp := func() {
		os.RemoveAll(tempDir)
		db.Close()
	}

	return cleanUp, db, tempDir, hStore, nil
}

func createTestFilterHeaderChain(numHeaders uint32) []*FilterHeader {
	filterHeaders := make([]*FilterHeader, numHeaders)
	for i := uint32(1); i <= numHeaders; i++ {
		filterHeaders[i-1] = &FilterHeader{
			HeaderHash: chainhash.DoubleHashH([]byte{byte(i)}),
			FilterHash: sha256.Sum256([]byte{byte(i)}),
			Height:     i,
		}
	}

	return filterHeaders
}

func TestFilterHeaderStoreOperations(t *testing.T) {
	cleanUp, _, _, fhs, err := createTestFilterHeaderStore()
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		t.Fatalf("unable to create new block header store: %v", err)
	}

	rand.Seed(time.Now().Unix())

	// With our test instance created, we'll now generate a series of
	// "fake" filter headers to insert into the database.
	const numHeaders = 100
	blockHeaders := createTestFilterHeaderChain(numHeaders)

	// With all the headers inserted, we'll now insert them into the
	// database in a single batch.
	if err := fhs.WriteHeaders(blockHeaders...); err != nil {
		t.Fatalf("unable to write block headers: %v", err)
	}

	// At this point, the _tip_ of the chain from the PoV of the database
	// should be the very last header we inserted.
	lastHeader := blockHeaders[len(blockHeaders)-1]
	tipHeader, tipHeight, err := fhs.ChainTip()
	if err != nil {
		t.Fatalf("unable to fetch chain tip")
	}
	if !bytes.Equal(lastHeader.FilterHash[:], tipHeader[:]) {
		t.Fatalf("tip height headers don't match up: "+
			"expected %v, got %v", lastHeader, tipHeader)
	}
	if tipHeight != lastHeader.Height {
		t.Fatalf("chain tip doesn't match: expected %v, got %v",
			lastHeader.Height, tipHeight)
	}

	// With all the headers written, we should be able to retrieve each
	// header according to its hash _and_ height.
	for _, header := range blockHeaders {
		dbHeader, err := fhs.FetchHeaderByHeight(header.Height)
		if err != nil {
			t.Fatalf("unable to fetch header by height: %v", err)
		}
		if !bytes.Equal(header.FilterHash[:], dbHeader[:]) {
			t.Fatalf("retrieved by height headers don't match up: "+
				"expected %v, got %v", header.FilterHash,
				dbHeader)
		}

		blockHash := header.HeaderHash
		dbHeader, err = fhs.FetchHeader(&blockHash)
		if err != nil {
			t.Fatalf("unable to fetch header by hash: %v", err)
		}
		if !bytes.Equal(dbHeader[:], header.FilterHash[:]) {
			t.Fatalf("retrieved by hash headers don't match up: "+
				"expected %v, got %v", spew.Sdump(header),
				spew.Sdump(dbHeader))
		}
	}

	// Finally, we'll test the roll back scenario. Roll back the chain by a
	// single block, the returned block stamp should exactly match the last
	// header inserted, and the current chain tip should be the second to
	// last header inserted.
	secondToLastHeader := blockHeaders[len(blockHeaders)-2]
	blockStamp, err := fhs.RollbackLastBlock()
	if err != nil {
		t.Fatalf("unable to rollback chain: %v", err)
	}
	if lastHeader.Height != uint32(blockStamp.Height) {
		t.Fatalf("chain tip doesn't match: expected %v, got %v",
			lastHeader.Height, blockStamp.Height)
	}
	if !bytes.Equal(lastHeader.FilterHash[:], blockStamp.Hash[:]) {
		t.Fatalf("header hashes don't match: expected %v, got %v",
			lastHeader.FilterHash, blockStamp.Hash)
	}
	tipHeader, tipHeight, err = fhs.ChainTip()
	if err != nil {
		t.Fatalf("unable to fetch chain tip")
	}
	if !bytes.Equal(secondToLastHeader.FilterHash[:], tipHeader[:]) {
		t.Fatalf("tip height headers don't match up: "+
			"expected %v, got %v", spew.Sdump(secondToLastHeader),
			spew.Sdump(tipHeader))
	}
	if tipHeight != secondToLastHeader.Height {
		t.Fatalf("chain tip doesn't match: expected %v, got %v",
			secondToLastHeader.Height, tipHeight)
	}
}

func TestFilterHeaderStoreRecovery(t *testing.T) {
	// In this test we want to exercise the ability of the filter header
	// store to recover in the face of a partial batch write (the headers
	// were written, but the index wasn't updated).
	cleanUp, db, tempDir, fhs, err := createTestFilterHeaderStore()
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		t.Fatalf("unable to create new block header store: %v", err)
	}

	// First we'll generate a test header chain of length 10, inserting it
	// into the header store.
	blockHeaders := createTestFilterHeaderChain(10)
	if err := fhs.WriteHeaders(blockHeaders...); err != nil {
		t.Fatalf("unable to write block headers: %v", err)
	}

	// Next, in order to simulate a partial write, we'll roll back the
	// internal index by 5 blocks.
	for i := 0; i < 5; i++ {
		if err := fhs.truncateIndex(); err != nil {
			t.Fatalf("unable to truncate index: %v", err)
		}
	}

	// Next, we'll re-create the block header store in order to trigger the
	// recovery logic.
	fhs, err = NewFilterHeaderStore(tempDir, db, RegularFilter, &chaincfg.SimNetParams)
	if err != nil {
		t.Fatalf("unable to re-create bhs: %v", err)
	}

	// The chain tip of this new instance should be of height 5, and match
	// the 5th to last filter header.
	tipHash, tipHeight, err := fhs.ChainTip()
	if err != nil {
		t.Fatalf("unable to get chain tip: %v", err)
	}
	if tipHeight != 5 {
		t.Fatalf("tip height mismatch: expected %v, got %v", 5, tipHeight)
	}
	prevHeaderHash := blockHeaders[5].FilterHash
	if bytes.Equal(prevHeaderHash[:], tipHash[:]) {
		t.Fatalf("block hash mismatch: expected %v, got %v",
			prevHeaderHash, tipHash[:])
	}
}
