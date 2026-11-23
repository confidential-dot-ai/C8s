package taattest

import (
	"fmt"
	"testing"
)

func TestHoldersTracksCounts(t *testing.T) {
	h := newHolders()
	h.add("a", "k1")
	h.add("a", "k2")
	h.add("a", "k2") // the same key twice is one entry
	h.add("b", "k3")

	if got := h.count("a"); got != 2 {
		t.Fatalf("count(a) = %d, want 2", got)
	}
	if got := h.clients(); got != 2 {
		t.Fatalf("clients = %d, want 2", got)
	}

	h.remove("a", "k1")
	h.remove("a", "k2")
	if got := h.count("a"); got != 0 {
		t.Fatalf("count(a) after removing both = %d, want 0", got)
	}
	if got := h.clients(); got != 1 {
		t.Fatalf("clients after a let go = %d, want 1", got)
	}
	h.remove("a", "gone") // removing what nobody holds changes nothing
	h.remove("nobody", "k3")
	if got := h.count("b"); got != 1 {
		t.Fatalf("count(b) = %d, want 1", got)
	}
}

// TestHoldersFollowsTheFullestClient pins the running maximum, which is what
// makes the admission decision O(1) instead of a scan: it has to fall when the
// client holding the most gives entries up.
func TestHoldersFollowsTheFullestClient(t *testing.T) {
	h := newHolders()
	for i := range 5 * minShare {
		h.add("big", fmt.Sprintf("k%d", i))
	}
	h.add("small", "s1")

	// Capacity 6*minShare over three entitled clients: the share is 2*minShare
	// and big is over it.
	if client, ok := h.admit(6*minShare, "newcomer"); !ok || client != "big" {
		t.Fatalf("admit = %q, %v; want big, true", client, ok)
	}
	// Capacity 30*minShare: the share is 10*minShare and nobody reaches it.
	if client, ok := h.admit(30*minShare, "newcomer"); ok {
		t.Fatalf("admit = %q, %v; want no client over its share", client, ok)
	}

	for i := range 5*minShare - 1 {
		h.remove("big", fmt.Sprintf("k%d", i))
	}
	// Both hold one now, well under the floor, so nothing is taken from them.
	if client, ok := h.admit(2, "newcomer"); ok {
		t.Fatalf("admit after big gave up its lead = %q, %v; want none", client, ok)
	}
	if h.max != 1 {
		t.Fatalf("running maximum is %d, want 1", h.max)
	}
}

// TestHoldersFloorTheShare pins the quantity an attacker cannot buy down. The
// share is capacity over a client count the attacker adds to, so without a
// floor its addresses decide how far an honest client is drained.
func TestHoldersFloorTheShare(t *testing.T) {
	const capacity = 8192
	h := newHolders()
	for i := range minShare {
		h.add("client:honest", fmt.Sprintf("honest-%d", i))
	}
	// Far more clients than capacity/minShare, each holding one: the unfloored
	// share here would be 1.
	for i := range 4000 {
		h.add(fmt.Sprintf("client:flooder-%d", i), "k")
	}

	if client, ok := h.admit(capacity, "client:newcomer"); ok {
		t.Fatalf("admit = %q; want nothing taken with every client at or under the floor of %d", client, minShare)
	}
}

// TestHoldersAdmitAClientHoldingNothing pins the other half: a full store
// counts the caller in the share it divides, so a client holding nothing is
// never the one refused while a holder is above that share.
func TestHoldersAdmitAClientHoldingNothing(t *testing.T) {
	const (
		capacity  = 8192
		perClient = 512
	)
	h := newHolders()
	// Sixteen clients at the per-client bound fill the store exactly, so every
	// holder is at capacity/16 and nobody is above it.
	for c := range capacity / perClient {
		client := fmt.Sprintf("client:holder-%d", c)
		for i := range perClient {
			h.add(client, fmt.Sprintf("%s-%d", client, i))
		}
	}
	if client, ok := h.admit(capacity, "client:newcomer"); !ok {
		t.Fatal("a client holding nothing was refused by a store whose holders are all at the per-client bound")
	} else if h.count(client) != perClient {
		t.Fatalf("admit chose %q holding %d, want one of the clients at %d", client, h.count(client), perClient)
	}
	// A client already holding its share is not entitled to more: it does not
	// add to the denominator, so nothing is above the share it asks against.
	if client, ok := h.admit(capacity, "client:holder-0"); ok {
		t.Fatalf("admit = %q for a client already at its share; want it refused", client)
	}
}

// TestHoldersLeaveNothingBehind pins that a client that has let everything go
// leaves no entry in either index. A per-client map that outlives its keys is
// the growth this bounding exists to stop, and the key is caller-chosen.
func TestHoldersLeaveNothingBehind(t *testing.T) {
	h := newHolders()
	for i := range 1000 {
		client := fmt.Sprintf("client:%d", i)
		h.add(client, "k")
		h.remove(client, "k")
	}
	if got := h.clients(); got != 0 {
		t.Fatalf("index holds %d clients after every one let go, want 0", got)
	}
	for size, clients := range h.bySize {
		if len(clients) != 0 {
			t.Fatalf("the size index still holds %d clients at size %d", len(clients), size)
		}
	}
	if h.max != 0 {
		t.Fatalf("the running maximum is %d, want 0", h.max)
	}
}

func TestHoldersOverShareOnAnEmptyIndex(t *testing.T) {
	h := newHolders()
	if client, ok := h.admit(10, "client:newcomer"); ok {
		t.Fatalf("admit on an empty index = %q, %v; want none", client, ok)
	}
}
