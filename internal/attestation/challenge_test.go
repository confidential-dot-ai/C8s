package attestation

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// raceRounds: two goroutines can only be inside a check-then-act window at
// once when they truly run at once, so this test's power comes from the
// parallelism of the runner. TestCreateReclaimsBeforeEvicting covers the same
// ordering deterministically.
func raceRounds() int {
	if runtime.GOMAXPROCS(0) >= 8 {
		return 500
	}
	return 200
}

func TestCreateReturns32Bytes(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()
	if got := len(challenge[:]); got != 32 {
		t.Fatalf("expected 32 bytes, got %d", got)
	}
}

func TestConsumeValidChallenge(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()

	if !store.Consume(challenge[:]) {
		t.Fatal("expected Consume to return true for valid challenge")
	}
}

func TestConsumeUnknownChallenge(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)

	unknown := [32]byte{0xff}
	if store.Consume(unknown[:]) {
		t.Fatal("expected Consume to return false for unknown challenge")
	}
}

func TestConsumeReusedChallenge(t *testing.T) {
	store := NewChallengeStore(5 * time.Minute)
	challenge := store.Create()

	if !store.Consume(challenge[:]) {
		t.Fatal("first consume should succeed")
	}
	if store.Consume(challenge[:]) {
		t.Fatal("second consume should fail (single use)")
	}
}

// TestCreateEvictsExpiredChallenges backdates a stored challenge past the TTL
// and checks the next Create removes it, so the map cannot grow unbounded.
func TestCreateEvictsExpiredChallenges(t *testing.T) {
	store := NewChallengeStore(time.Hour)
	old := store.Create()
	store.mu.Lock()
	store.challenges[old] = time.Now().Add(-2 * time.Hour)
	store.mu.Unlock()

	fresh := store.Create()

	store.mu.Lock()
	_, oldKept := store.challenges[old]
	_, freshKept := store.challenges[fresh]
	n := len(store.challenges)
	store.mu.Unlock()

	if oldKept {
		t.Error("expired challenge was not evicted by Create")
	}
	if !freshKept {
		t.Error("fresh challenge missing after Create")
	}
	if n != 1 {
		t.Errorf("store holds %d challenges, want 1", n)
	}
}

// entitledChallenges is the number of challenges a fleet may have outstanding
// inside one TTL, stated here rather than derived from the bound so that
// shrinking the bound fails this test. Every pod that starts, renews a
// certificate or fetches a secret takes one.
const entitledChallenges = 100000

// challengeEntryBytes is a key, a timestamp and the queue slot behind it;
// challengeBudget is what the store may cost CDS, which holds the mesh CA in
// the same process.
const (
	challengeEntryBytes = 112
	challengeBudget     = 32 << 20
)

// TestChallengeStoreStaysInsideItsBudget pins the bound from above: it exists
// to stop unauthenticated traffic becoming memory, so it has to stay small
// enough to do that.
func TestChallengeStoreStaysInsideItsBudget(t *testing.T) {
	// The queue may carry twice the map between compactions.
	if cost := 2 * maxChallenges * challengeEntryBytes; cost > challengeBudget {
		t.Fatalf("the challenge store may cost %d bytes, over its budget of %d", cost, challengeBudget)
	}
}

// TestAStoreHoldsAFleetsWorthOfChallenges pins the bound against that number:
// below it, a cluster-wide restart would have callers' challenges dropped
// before they could redeem them.
func TestAStoreHoldsAFleetsWorthOfChallenges(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	first := store.Create()
	for i := 1; i < entitledChallenges; i++ {
		store.Create()
	}

	store.mu.Lock()
	held := len(store.challenges)
	store.mu.Unlock()
	if held != entitledChallenges {
		t.Fatalf("store holds %d challenges of %d issued, want all of them", held, entitledChallenges)
	}
	if !store.Consume(first[:]) {
		t.Fatal("the first challenge of the fleet was dropped before it could be redeemed")
	}
}

// TestCreateEvictsTheOldestAtCapacity fills the store to its bound and checks
// minting keeps working there, that the store stays at the bound, and that the
// challenge dropped is the oldest.
func TestCreateEvictsTheOldestAtCapacity(t *testing.T) {
	store := NewChallengeStore(time.Hour)
	oldest := store.Create()
	second := store.Create()
	for i := 2; i < maxChallenges; i++ {
		store.Create()
	}

	store.mu.Lock()
	atCap := len(store.challenges)
	store.mu.Unlock()
	if atCap != maxChallenges {
		t.Fatalf("store holds %d challenges after filling, want %d", atCap, maxChallenges)
	}

	newest := store.Create()

	store.mu.Lock()
	held, queued := len(store.challenges), len(store.issued)
	_, oldestKept := store.challenges[oldest]
	_, newestKept := store.challenges[newest]
	store.mu.Unlock()

	if held != maxChallenges {
		t.Fatalf("store holds %d challenges past the bound, want %d", held, maxChallenges)
	}
	if queued > maxChallenges {
		t.Fatalf("issued holds %d keys, want at most %d", queued, maxChallenges)
	}
	if oldestKept {
		t.Fatal("the oldest challenge survived a mint at the bound")
	}
	if !newestKept {
		t.Fatal("the challenge minted at the bound was not stored")
	}
	if !store.Consume(second[:]) {
		t.Fatal("the second-oldest challenge was dropped as well")
	}
}

// TestCreateHoldsTheBoundUnderConcurrency releases a crowd of minters at a
// store one under its bound, round after round: the bound check and the insert
// must be one critical section, or a round where two of them read the same
// free slot leaves the store over its bound for good.
func TestCreateHoldsTheBoundUnderConcurrency(t *testing.T) {
	const minters = 256
	store := NewChallengeStore(time.Hour)
	for range maxChallenges {
		store.Create()
	}

	for round := 0; round < raceRounds(); round++ {
		store.mu.Lock()
		for len(store.issued) >= maxChallenges {
			store.dropOldest()
		}
		store.mu.Unlock()

		var wg sync.WaitGroup
		start := make(chan struct{})
		for range minters {
			wg.Go(func() {
				<-start
				store.Create()
			})
		}
		close(start)
		wg.Wait()

		store.mu.Lock()
		held, queued := len(store.challenges), len(store.issued)
		store.mu.Unlock()
		if held != maxChallenges {
			t.Fatalf("round %d: store holds %d challenges, want %d", round, held, maxChallenges)
		}
		if queued != maxChallenges {
			t.Fatalf("round %d: issued holds %d keys, want %d", round, queued, maxChallenges)
		}
	}
}

// TestCreateReclaimsBeforeEvicting pins the order inside Create: expired
// challenges are reclaimed first, and only a store still at its bound gives up
// a live one. Deciding that on a count read before the reclaim costs a caller
// a challenge that the expiry had already made room for.
func TestCreateReclaimsBeforeEvicting(t *testing.T) {
	store := NewChallengeStore(time.Hour)
	expiring := store.Create()
	survivor := store.Create()
	for i := 2; i < maxChallenges; i++ {
		store.Create()
	}

	store.mu.Lock()
	store.challenges[expiring] = time.Now().Add(-2 * time.Hour)
	store.mu.Unlock()

	store.Create()

	store.mu.Lock()
	held := len(store.challenges)
	store.mu.Unlock()
	if held != maxChallenges {
		t.Fatalf("store holds %d challenges, want %d", held, maxChallenges)
	}
	if !store.Consume(survivor[:]) {
		t.Fatal("a live challenge was evicted although an expired one had freed room")
	}
}

// TestCompactionKeepsLiveChallengesInOrder drives the queue past the length
// that compacts it, with live challenges interleaved among consumed ones.
// Compaction's job is to keep exactly the live keys and their order: dropping
// one costs a caller a challenge it holds, and reordering makes the oldest no
// longer the one at the front.
func TestCompactionKeepsLiveChallengesInOrder(t *testing.T) {
	store := NewChallengeStore(time.Hour)

	// A live challenge often enough that a compaction retains thousands of
	// them, the rest consumed straight away, for well past the 2*maxChallenges
	// the queue compacts at.
	const liveEvery = 100
	var live [][32]byte
	for i := range 3 * maxChallenges {
		challenge := store.Create()
		if i%liveEvery == 0 {
			live = append(live, challenge)
			continue
		}
		if !store.Consume(challenge[:]) {
			t.Fatalf("challenge %d did not consume", i)
		}
	}

	store.mu.Lock()
	held, queued := len(store.challenges), len(store.issued)
	order := append([][32]byte(nil), store.issued...)
	store.mu.Unlock()

	// Counted from what was minted and not consumed, so a compaction that
	// drops a live key from both the map and the queue is still caught.
	if held != len(live) {
		t.Fatalf("store holds %d challenges, want the %d minted and never consumed", held, len(live))
	}
	if queued > 2*maxChallenges {
		t.Fatalf("the queue holds %d keys, over its bound of %d", queued, 2*maxChallenges)
	}
	// Between compactions the queue also carries keys Consume removed; the
	// live ones inside it must still be all of them, in the order they were
	// minted, since that is what makes the front of the queue the oldest.
	var survived [][32]byte
	store.mu.Lock()
	for _, key := range order {
		if _, ok := store.challenges[key]; ok {
			survived = append(survived, key)
		}
	}
	store.mu.Unlock()
	if len(survived) != len(live) {
		t.Fatalf("the queue names %d live challenges, want %d", len(survived), len(live))
	}
	for i := range survived {
		if survived[i] != live[i] {
			t.Fatalf("live position %d in the queue is a different challenge than the %d-th minted", i, i)
		}
	}
	for i, challenge := range live {
		if !store.Consume(challenge[:]) {
			t.Fatalf("live challenge %d of %d was dropped by a compaction", i, len(live))
		}
	}
}

// TestConsumedChallengesDoNotOccupyCapacity mints and consumes far more
// challenges than the bound while holding one back. A consumed challenge that
// keeps its slot would fill the store with nothing, and the one live challenge
// would be evicted to make room for a mint.
func TestConsumedChallengesDoNotOccupyCapacity(t *testing.T) {
	store := NewChallengeStore(time.Hour)
	kept := store.Create()

	for i := range 3 * maxChallenges {
		challenge := store.Create()
		if !store.Consume(challenge[:]) {
			t.Fatalf("challenge %d did not consume", i)
		}
		// Checked as it goes: a queue that keeps consumed keys grows until the
		// eviction scan makes the run quadratic, and this test would look
		// wedged for minutes instead of failing here.
		if i%4096 == 0 {
			store.mu.Lock()
			queued := len(store.issued)
			store.mu.Unlock()
			if queued > 2*maxChallenges {
				t.Fatalf("after %d mints the queue holds %d keys, over its bound of %d", i, queued, 2*maxChallenges)
			}
		}
	}

	store.mu.Lock()
	held, queued := len(store.challenges), len(store.issued)
	store.mu.Unlock()
	if held != 1 {
		t.Fatalf("store holds %d challenges, want the one never consumed", held)
	}
	if queued > 2*maxChallenges {
		t.Fatalf("issued holds %d keys, over its bound of %d", queued, 2*maxChallenges)
	}
	if !store.Consume(kept[:]) {
		t.Fatal("the challenge held back was evicted by mints that were consumed straight away")
	}
}

// TestConsumedChallengesLeaveNoResidue pins the same reclaim from the other
// side: consuming everything leaves neither the map nor the queue holding it.
func TestConsumedChallengesLeaveNoResidue(t *testing.T) {
	store := NewChallengeStore(time.Hour)
	for i := range 3 * maxChallenges {
		challenge := store.Create()
		if !store.Consume(challenge[:]) {
			t.Fatalf("challenge %d did not consume", i)
		}
	}

	store.mu.Lock()
	held, queued := len(store.challenges), len(store.issued)
	store.mu.Unlock()
	if held != 0 {
		t.Fatalf("store holds %d challenges after consuming every one", held)
	}
	// The last key is still queued, since nothing has minted after it; every
	// other consumed key must have been shed.
	if queued > 1 {
		t.Fatalf("issued holds %d keys after consuming every one, want at most 1", queued)
	}
}

func TestConsumeExpiredChallenge(t *testing.T) {
	store := NewChallengeStore(1 * time.Millisecond)
	challenge := store.Create()

	time.Sleep(10 * time.Millisecond)

	if store.Consume(challenge[:]) {
		t.Fatal("expected Consume to return false for expired challenge")
	}
}
