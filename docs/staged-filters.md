# Experimental staged compact filters

Wallet rescans and `GetUtxo` can request the staged form of a BIP158 basic
filter from a designated regtest or simnet peer. Start the serving node with
its experimental staged-filter option (`--experimentalprogressivecfilters`
in btcd), then configure Neutrino to connect to that node.

```go
config.ChainParams = chaincfg.SimNetParams
config.ConnectPeers = []string{"127.0.0.1:18555"}
config.StagedFilters = &neutrino.StagedFilterConfig{
    Peer: "127.0.0.1:18555",
}
```

A historical scan can request the same stage for up to 16 consecutive blocks
with synced filter headers. A single block uses `getcfstage`. Both request
forms receive individual `cfstage` replies over the existing peer connection.
If the peer is unavailable, sends invalid data, or exceeds the configured
lookup timeout, the scan tries the regular BIP157 compact filter path. The
staged matcher caches authenticated full filters in memory.

With ordinary BIP157 filter headers, Neutrino reconstructs all four stages,
serializes the result as a BIP158 filter, and checks it against the accepted
filter header before matching. An optional `Stage0Commitment` callback can
provide a trusted stage-zero digest and the basic filter hash for the same
block. The client checks the basic hash against its local filter header and
the received stage against the digest. Only then can a prefix miss skip
refinement. The authority providing the commitment must derive the prefix
accurately from the authenticated basic filter. Obtain the callback's data
through an independently authenticated source.

A stage-zero digest is SHA256d of the ASCII domain `cfilter-stage0/v1`
followed by one zero byte, the raw 32-byte block hash, the raw 32-byte basic
filter hash, the CompactSize element count, and the exact stage-zero payload,
in order. A matched prefix still requires full BIP158 authentication and
candidate block verification.

The matcher uses portable SipHash-to-range mapping by default. An amd64 build
with `GOEXPERIMENT=simd` can use the vector implementation when the CPU has the
required AVX-512 features and the watch list has enough supported scripts.
