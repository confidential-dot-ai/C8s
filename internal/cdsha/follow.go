package cdsha

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// ErrNotExtending is a served chain that does not extend the one a reader
// already verified: a rollback, or another branch.
var ErrNotExtending = errors.New("the replica serves a chain that does not extend the one verified before")

// Follow reads the chain at url after known (nil: from genesis) and returns
// the state at the head a serving replica of an accepted build confirms. A
// chain read from genesis must hold pin, unless pin is nil.
// The entries are read over plain, since they verify by signature; the head
// is confirmed over attested(pins at that head), so an entry that lost its
// compare-and-swap, or a tail only the host serves, is never taken.
func Follow(ctx context.Context, url string, pin *cdschain.Head, known *cdschain.State, plain *http.Client, attested func(armtls.Pins) (*http.Client, error)) (*cdschain.State, error) {
	var got []cdschain.Entry
	fetch := true
	for range 4 {
		if fetch {
			more, err := ReadChain(ctx, plain, url, next(known)+uint64(len(got)))
			if err != nil {
				return nil, err
			}
			got = append(got, more...)
		}
		state, err := extend(known, got, pin)
		if err != nil {
			return nil, err
		}
		client, err := attested(armtls.Pins(state.Pins().Policy()))
		if err != nil {
			return nil, err
		}
		var status Status
		err = Call(ctx, client, http.MethodGet, url+StatusPath, nil, &status)
		client.CloseIdleConnections()
		switch {
		case err != nil:
			return nil, err
		case status.Serving != "" || status.Held == nil:
			return nil, fmt.Errorf("the replica serves nothing: %s", status.Serving)
		case status.Held.Seq > state.Head.Seq:
			fetch = true
			continue
		}
		cut := int(status.Held.Seq - next(known) + 1)
		if known != nil && status.Held.Seq < known.Head.Seq {
			return nil, ErrNotExtending
		}
		if cut < 0 || cut > len(got) || (cut > 0 && got[cut-1].Hash() != status.Held.Hash) || (cut == 0 && known.Head != *status.Held) {
			return nil, fmt.Errorf("%w: the confirmed head %d is not in it", ErrNotExtending, status.Held.Seq)
		}
		if cut == len(got) {
			return state, nil
		}
		// The confirmed head is older than the chain read: cut the tail
		// and confirm again under the pins of the cut state.
		got, fetch = got[:cut], false
	}
	return nil, errors.New("the replica set's head kept moving; try again")
}

func next(known *cdschain.State) uint64 {
	if known == nil {
		return 0
	}
	return known.Head.Seq + 1
}

func ReadChain(ctx context.Context, client *http.Client, url string, from uint64) ([]cdschain.Entry, error) {
	var all []cdschain.Entry
	for size := 0; ; {
		var page Chain
		if err := call(ctx, client, http.MethodGet, url+ChainPath+"?from="+strconv.FormatUint(from+uint64(len(all)), 10), nil, &page, maxPage); err != nil {
			return nil, err
		}
		for _, e := range page.Entries {
			size += len(e.Body) + len(e.Sig)
		}
		// The pages are not verified yet: their total is bounded too.
		if size > maxChainRead {
			return nil, fmt.Errorf("the chain read passed %d bytes", maxChainRead)
		}
		all = append(all, page.Entries...)
		if len(page.Entries) < chainPage {
			return all, nil
		}
	}
}

// maxChainRead caps a whole chain read, before it is verified.
var maxChainRead = maxAnswer

// maxPage caps one chain page: chainPage entries at most, base64-encoded.
const maxPage = chainPage * cdschain.MaxEntryBytes * 2

// extend verifies entries after known, holding a new chain to pin.
func extend(known *cdschain.State, entries []cdschain.Entry, pin *cdschain.Head) (*cdschain.State, error) {
	state, rest := known, entries
	if known == nil {
		if len(entries) == 0 {
			return nil, errors.New("the replica served no genesis")
		}
		var err error
		if state, err = cdschain.VerifyGenesis(entries[0]); err != nil {
			return nil, err
		}
		rest = entries[1:]
	}
	for i, e := range rest {
		s, err := state.Apply(e)
		if i == 0 && known != nil && errors.Is(err, cdschain.ErrNotNext) {
			return nil, ErrNotExtending
		}
		if err != nil {
			return nil, err
		}
		state = s
	}
	if p := pin; known == nil && p != nil && (p.Seq >= uint64(len(entries)) || entries[p.Seq].Hash() != p.Hash) {
		return nil, fmt.Errorf("the chain does not hold the pinned entry %d (%s)", p.Seq, p.Hash)
	}
	return state, nil
}
