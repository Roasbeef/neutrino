package bridge

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/neutrino/rescan"
	"github.com/stretchr/testify/require"
)

// TestRealActorLifecycleConformsToModelInvariants exercises the real actor
// through the bridge harness and checks a subset of the P-model invariants
// against the actual Go callbacks.
func TestRealActorLifecycleConformsToModelInvariants(
	t *testing.T,
) {

	harness, err := NewActorHarness(6, ActorHarnessConfig{
		BatchSize: 100,
	})
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	events := harness.Recorder.Events()

	errs := CheckFilteredBlockForEveryBlock(events)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckBlockCallbackConsistency(events)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckMonotonicFilteredProgress(events)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	harness.StopAndWait()

	subErrs := CheckSubscriptionAlternation(
		harness.Chain.SubscriptionEvents(),
	)
	require.Empty(
		t,
		subErrs,
		"subscription lifecycle errors: %v",
		subErrs,
	)

	require.EqualValues(t, 1, harness.Chain.SubscribeCount(),
		"expected exactly one subscription start")
	require.EqualValues(
		t,
		1,
		harness.Chain.CancelCount(),
		"expected stop to cancel the active subscription",
	)
}

// TestRealActorRewindFindsHistoricalTx proves the bridge can drive a
// model-style "add watch + rewind" scenario against the actual Go actor.
func TestRealActorRewindFindsHistoricalTx(t *testing.T) {
	chain := NewMockChain(6)

	addr, err := address.NewAddressPubKeyHash(
		chainhash.HashB([]byte("bridge-rewind"))[:20],
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	txStamp, _, err := chain.AddBlockWithTx(addr)
	require.NoError(t, err)

	harness, err := NewActorHarnessWithChain(
		chain,
		ActorHarnessConfig{
			BatchSize: 100,
		},
	)
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	rewindTo := uint32(txStamp.Height - 1)
	err = harness.Actor.AddWatchAddrs(t.Context(), rescan.WatchUpdate{
		Addrs:    []address.Address{addr},
		RewindTo: &rewindTo,
	})
	require.NoError(t, err)

	require.Eventually(
		t,
		func() bool {
			for _, event := range harness.Recorder.Events() {
				if event.Kind ==
					ObservedFilteredBlockConnected &&
					event.Height == txStamp.Height &&
					event.RelevantTxCount > 0 {

					return true
				}
			}

			return false
		},
		10*time.Second,
		10*time.Millisecond,
		"expected rewind to rediscover the historical transaction",
	)

	errs := CheckFilteredBlockForEveryBlock(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckMonotonicFilteredProgress(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	harness.StopAndWait()
}

// TestCurrentAddWatchNoOpRewindDoesNotRestartSubscription checks a direct
// model/code consistency rule: in the P model, a rewind request at or above
// the current height is a no-op while Current. The real actor should not
// cancel and recreate its subscription for that case.
func TestCurrentAddWatchNoOpRewindDoesNotRestartSubscription(
	t *testing.T,
) {

	harness, err := NewActorHarness(6, ActorHarnessConfig{
		BatchSize: 100,
	})
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	initialSubscribeCount := harness.Chain.SubscribeCount()
	initialCancelCount := harness.Chain.CancelCount()
	initialFinishedCount := harness.Recorder.FinishedCount()

	// Use a no-op rewind target equal to the current tip.
	state, err := harness.Actor.CurrentState(t.Context())
	require.NoError(t, err)

	cur, ok := state.(*rescan.StateCurrent)
	require.True(t, ok)

	addr, err := address.NewAddressPubKeyHash(
		chainhash.HashB([]byte("bridge-noop-rewind"))[:20],
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	rewindTo := uint32(cur.CurStamp.Height)
	err = harness.Actor.AddWatchAddrs(t.Context(), rescan.WatchUpdate{
		Addrs:    []address.Address{addr},
		RewindTo: &rewindTo,
	})
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	require.Equal(
		t,
		initialSubscribeCount,
		harness.Chain.SubscribeCount(),
		"no-op rewind should not restart subscription",
	)
	require.Equal(
		t,
		initialCancelCount,
		harness.Chain.CancelCount(),
		"no-op rewind should not cancel subscription",
	)
	require.Equal(
		t,
		initialFinishedCount,
		harness.Recorder.FinishedCount(),
		"no-op rewind should not "+
			"emit an extra "+
			"rescan-finished callback",
	)

	harness.StopAndWait()
}

// TestBlockCallbacksPreserveHeaderIdentity verifies that the actor dispatches
// both block callbacks for the same concrete block even if the chain's
// height-based lookup changes between them.
func TestBlockCallbacksPreserveHeaderIdentity(t *testing.T) {
	harness, err := NewActorHarness(3, ActorHarnessConfig{
		BatchSize: 100,
	})
	require.NoError(t, err)

	// Change the active lookup only during dispatch. The next scan step
	// checks ancestry, so restore the height before the turn completes.
	rewrote := make(chan error, 1)
	var (
		rewriteAttempted bool
		restore          func()
	)
	harness.Recorder.SetOnObserved(func(event ObservedEvent) {
		if event.Height != 1 {
			return
		}

		switch event.Kind {
		case ObservedFilteredBlockConnected:
			if rewriteAttempted {
				return
			}
			rewriteAttempted = true
			var err error
			restore, err = harness.Chain.RewriteHeaderAtHeight(1)
			rewrote <- err

		case ObservedBlockConnected:
			if restore != nil {
				restore()
				restore = nil
			}
		}
	})

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))
	select {
	case err := <-rewrote:
		require.NoError(t, err)
	default:
		t.Fatal("height lookup was never rewritten")
	}

	errs := CheckBlockCallbackConsistency(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"callback consistency errors: %v",
		errs,
	)

	harness.StopAndWait()
}

// TestRecoveredBlockRetryDoesNotReError ensures a block that was recovered via
// rewind/sync does not later trip the retry timer as a stale error.
func TestRecoveredBlockRetryDoesNotReError(t *testing.T) {
	chain := NewMockChain(3)

	var errorCount atomic.Int32
	dummyAddr, err := address.NewAddressPubKeyHash(
		chainhash.HashB([]byte("bridge-retry-dummy"))[:20],
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	harness, err := NewActorHarnessWithChain(
		chain,
		ActorHarnessConfig{
			BatchSize:  100,
			WatchAddrs: []address.Address{dummyAddr},
			OnError: func(err error) {
				errorCount.Add(1)
			},
		},
	)
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	newTip := chain.AddBlock()
	require.NoError(
		t,
		// Fail the live fetch and the first fetch after falling back to
		// historical sync. The latter is reported and arms the retry.
		chain.FailFilterFetches(uint32(newTip.Height), 2),
	)
	require.NoError(
		t,
		chain.NotifyBlockConnected(
			uint32(newTip.Height),
		),
	)

	require.Eventually(
		t,
		func() bool {
			return errorCount.Load() >= 1
		},
		2*time.Second,
		10*time.Millisecond,
		"expected the injected "+
			"filter failure to hit "+
			"the actor retry path",
	)

	rewindTo := uint32(newTip.Height - 2)
	err = harness.Actor.AddWatchAddrs(t.Context(), rescan.WatchUpdate{
		RewindTo: &rewindTo,
	})
	require.NoError(t, err)

	require.Eventually(
		t,
		func() bool {
			state, err := harness.Actor.CurrentState(t.Context())
			if err != nil {
				return false
			}

			cur, ok := state.(*rescan.StateCurrent)
			return ok &&
				cur.CurStamp.Height == newTip.Height
		},
		5*time.Second,
		10*time.Millisecond,
		"expected rewind/sync path to recover the failed block",
	)

	stableErrors := errorCount.Load()
	time.Sleep(3500 * time.Millisecond)

	require.Equal(
		t,
		stableErrors,
		errorCount.Load(),
		"stale retry should not re-error after block was recovered",
	)

	errs := CheckMonotonicFilteredProgress(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	harness.StopAndWait()
}

// TestDuplicateCurrentTipNotificationIsIgnored ensures that replaying the
// current tip through the notification bridge does not emit duplicate forward
// callbacks or kick the actor into an error/retry loop.
func TestDuplicateCurrentTipNotificationIsIgnored(t *testing.T) {
	var errorCount atomic.Int32

	harness, err := NewActorHarness(4, ActorHarnessConfig{
		BatchSize: 100,
		OnError: func(err error) {
			errorCount.Add(1)
		},
	})
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	state, err := harness.Actor.CurrentState(t.Context())
	require.NoError(t, err)

	cur, ok := state.(*rescan.StateCurrent)
	require.True(t, ok)

	initialEvents := len(harness.Recorder.Events())
	initialFinishedCount := harness.Recorder.FinishedCount()

	require.NoError(t, harness.Chain.NotifyBlockConnected(
		uint32(cur.CurStamp.Height),
	))

	time.Sleep(200 * time.Millisecond)

	require.Zero(
		t,
		errorCount.Load(),
		"duplicate current-tip notification should be ignored",
	)
	require.Len(
		t,
		harness.Recorder.Events(),
		initialEvents,
		"duplicate current-tip notification should not emit callbacks",
	)
	require.Equal(
		t,
		initialFinishedCount,
		harness.Recorder.FinishedCount(),
		"duplicate current-tip "+
			"notification should not "+
			"emit rescan-finished",
	)

	nextTip := harness.Chain.AddBlock()
	require.NoError(t, harness.Chain.NotifyBlockConnected(
		uint32(nextTip.Height),
	))

	require.Eventually(
		t,
		func() bool {
			events := harness.Recorder.Events()
			if len(events) == 0 {
				return false
			}

			last := events[len(events)-1]
			return last.Kind == ObservedBlockConnected &&
				last.Height == nextTip.Height
		},
		5*time.Second,
		10*time.Millisecond,
		"expected actor to keep advancing after duplicate notification",
	)

	errs := CheckFilteredBlockForEveryBlock(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckBlockCallbackConsistency(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckMonotonicFilteredProgress(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	harness.StopAndWait()
}

// TestSubscriptionLifecycleRetainedAcrossRewind checks that the actor keeps
// its subscription across rewind and cancels it on shutdown.
func TestSubscriptionLifecycleRetainedAcrossRewind(
	t *testing.T,
) {

	harness, err := NewActorHarness(6, ActorHarnessConfig{
		BatchSize: 100,
	})
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	state, err := harness.Actor.CurrentState(t.Context())
	require.NoError(t, err)

	cur, ok := state.(*rescan.StateCurrent)
	require.True(t, ok)

	initialFinished := harness.Recorder.FinishedCount()
	rewindTo := uint32(2)

	err = harness.Actor.AddWatchAddrs(t.Context(), rescan.WatchUpdate{
		RewindTo: &rewindTo,
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return harness.Recorder.FinishedCount() >= initialFinished+1
	}, 5*time.Second, 10*time.Millisecond,
		"expected rewind cycle to finish")

	harness.StopAndWait()

	subEvents := harness.Chain.SubscriptionEvents()
	subErrs := CheckSubscriptionAlternation(subEvents)
	require.Empty(
		t,
		subErrs,
		"subscription lifecycle errors: %v",
		subErrs,
	)

	require.Equal(t, int32(5), cur.CurStamp.Height)
	require.Len(
		t,
		subEvents,
		2,
		"expected one subscription throughout scanning and rewind",
	)
	require.Equal(t, SubscriptionStarted, subEvents[0].Kind)
	require.Zero(t, subEvents[0].Height)
	require.Equal(t, SubscriptionCanceled, subEvents[1].Kind)
}

// TestDisconnectCallbacksStayPairedAcrossReattach proves the real actor emits
// both disconnect callbacks for the same block and can resume forward progress
// after the tip is detached and reattached through the bridge.
func TestDisconnectCallbacksStayPairedAcrossReattach(
	t *testing.T,
) {

	harness, err := NewActorHarness(6, ActorHarnessConfig{
		BatchSize: 100,
	})
	require.NoError(t, err)

	t.Cleanup(harness.StopAndWait)
	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	state, err := harness.Actor.CurrentState(t.Context())
	require.NoError(t, err)

	cur, ok := state.(*rescan.StateCurrent)
	require.True(t, ok)

	tipHeight := uint32(cur.CurStamp.Height)

	require.NoError(
		t,
		harness.Chain.NotifyBlockDisconnected(tipHeight),
	)

	require.Eventually(
		t,
		func() bool {
			state, err := harness.Actor.CurrentState(t.Context())
			if err != nil {
				return false
			}

			cur, ok := state.(*rescan.StateCurrent)
			return ok &&
				cur.CurStamp.Height == int32(
					tipHeight-1,
				)
		},
		5*time.Second,
		10*time.Millisecond,
		"expected actor to rewind one block after disconnect",
	)

	require.NoError(
		t,
		harness.Chain.NotifyBlockConnected(tipHeight),
	)

	require.Eventually(
		t,
		func() bool {
			state, err := harness.Actor.CurrentState(t.Context())
			if err != nil {
				return false
			}

			cur, ok := state.(*rescan.StateCurrent)
			return ok &&
				cur.CurStamp.Height == int32(
					tipHeight,
				)
		},
		5*time.Second,
		10*time.Millisecond,
		"expected actor to reattach the disconnected block",
	)

	errs := CheckDisconnectCallbackConsistency(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"disconnect callback consistency errors: %v",
		errs,
	)

	errs = CheckFilteredBlockForEveryBlock(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckBlockCallbackConsistency(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	errs = CheckMonotonicFilteredProgress(
		harness.Recorder.Events(),
	)
	require.Empty(
		t,
		errs,
		"bridge invariant errors: %v",
		errs,
	)

	harness.StopAndWait()
}

// TestSubscriptionClosureAndCallerRestart exercises the supervisor boundary
// modeled by the P closure recovery case. The actor reports chain shutdown;
// the caller resumes from the scanned cursor when a chain is available again.
func TestSubscriptionClosureAndCallerRestart(t *testing.T) {
	errs := make(chan error, 1)
	var reported atomic.Int32
	harness, err := NewActorHarness(6, ActorHarnessConfig{
		BatchSize: 100,
		OnError: func(err error) {
			if reported.Add(1) == 1 {
				errs <- err
			}
		},
	})
	require.NoError(t, err)
	t.Cleanup(harness.StopAndWait)

	harness.Start()
	require.NoError(t, harness.WaitForCurrent(5*time.Second))

	state, err := harness.Actor.CurrentState(t.Context())
	require.NoError(t, err)
	current, ok := state.(*rescan.StateCurrent)
	require.True(t, ok)
	saved := current.CurStamp
	priorEvents := harness.Recorder.Events()
	newTip := harness.Chain.CloseActiveSubscriptionAndAddBlock()

	select {
	case <-harness.Actor.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("expected subscription closure to end the actor")
	}

	harness.StopAndWait()
	require.ErrorIs(t, harness.Actor.Err(), rescan.ErrSubscriptionClosed)
	require.EqualValues(t, 1, harness.Chain.SubscribeCount())
	require.EqualValues(t, 1, harness.Chain.CancelCount())
	require.Equal(t, priorEvents, harness.Recorder.Events())
	select {
	case err := <-errs:
		require.ErrorIs(t, err, rescan.ErrSubscriptionClosed)
	default:
		t.Fatal("expected the actor to report the subscription closure")
	}
	require.EqualValues(t, 1, reported.Load())

	// Start a new rescan from the caller's saved height. The replacement
	// subscribes without backlog and catches up via the stored headers.
	restarted, err := NewActorHarnessWithChain(harness.Chain,
		ActorHarnessConfig{
			StartHeight: uint32(saved.Height),
			BatchSize:   100,
		},
	)
	require.NoError(t, err)
	t.Cleanup(restarted.StopAndWait)
	restarted.Start()
	require.NoError(t, restarted.WaitForCurrent(5*time.Second))

	state, err = restarted.Actor.CurrentState(t.Context())
	require.NoError(t, err)
	current, ok = state.(*rescan.StateCurrent)
	require.True(t, ok)
	require.Equal(t, newTip.Height, current.CurStamp.Height)
	require.Equal(t, newTip.Hash, current.CurStamp.Hash)

	recoveredEvents := restarted.Recorder.Events()
	require.Equal(t, []ObservedEvent{
		{
			Kind:   ObservedFilteredBlockConnected,
			Height: newTip.Height,
			Hash:   newTip.Hash,
		},
		{
			Kind:   ObservedBlockConnected,
			Height: newTip.Height,
			Hash:   newTip.Hash,
		},
		{
			Kind:   ObservedRescanFinished,
			Height: newTip.Height,
		},
	}, recoveredEvents)

	events := append(priorEvents, recoveredEvents...)
	require.Empty(t, CheckFilteredBlockForEveryBlock(events))
	require.Empty(t, CheckBlockCallbackConsistency(events))
	require.Empty(t, CheckMonotonicFilteredProgress(events))

	restarted.StopAndWait()
	require.Empty(t, CheckSubscriptionAlternation(
		harness.Chain.SubscriptionEvents(),
	))
	require.EqualValues(t, 2, harness.Chain.SubscribeCount())
	require.EqualValues(t, 2, harness.Chain.CancelCount())
}

// TestMockSubscriptionZeroHeightMatchesProduction checks the production
// convention that a zero-height subscription has no historical backlog.
func TestMockSubscriptionZeroHeightMatchesProduction(
	t *testing.T,
) {

	chain := NewMockChain(4)
	sub, err := chain.Subscribe(0)
	require.NoError(t, err)
	select {
	case notification := <-sub.Notifications:
		t.Fatalf(
			"unexpected zero-height backlog notification: %v",
			notification,
		)
	default:
	}
	sub.Cancel()

	sub, err = chain.Subscribe(1)
	require.NoError(t, err)
	defer sub.Cancel()
	for _, height := range []uint32{2, 3} {
		select {
		case notification := <-sub.Notifications:
			require.Equal(
				t,
				height,
				notification.Height(),
			)
		default:
			t.Fatalf(
				"missing backlog notification at height %d",
				height,
			)
		}
	}
}
