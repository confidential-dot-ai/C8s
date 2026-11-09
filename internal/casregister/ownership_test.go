package casregister

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type pausedAcceptor struct {
	Peer
	entered  chan struct{}
	release  chan struct{}
	observed chan []byte
}

// Pauses an already-dispatched acceptance before the receiver copies its payload.
func (p pausedAcceptor) Accept(
	_ context.Context,
	cluster string,
	ballot Ballot,
	value []byte,
) error {
	close(p.entered)
	select {
	case <-p.release:
	case <-time.After(time.Second):
		return errors.New("paused acceptance timed out")
	}
	value = bytes.Clone(value)
	p.observed <- value
	late, cancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancel()
	return p.Peer.Accept(
		late,
		cluster,
		ballot,
		value,
	)
}

func TestReturnedValueDoesNotAliasPendingAcceptance(t *testing.T) {
	acceptors, _ := authorities(t)
	paused := pausedAcceptor{
		Peer:    acceptors[2],
		entered: make(chan struct{}),
		release: make(chan struct{}),
		observed: make(
			chan []byte,
			1,
		),
	}
	p := proposer(
		t,
		[]Peer{
			acceptors[0],
			acceptors[1],
			paused,
		},
	)
	want := []byte("committed opaque value")
	result, err := p.Update(
		context.Background(),
		func([]byte) ([]byte, error) {
			// Ensure the preceding prepare RPCs have released all dispatch slots.
			deadline := time.Now().Add(time.Second)
			for len(p.slots[0])+len(p.slots[1])+len(p.slots[2]) != 0 {
				if time.Now().After(deadline) {
					return nil, errors.New("prepare workers did not finish")
				}
				time.Sleep(time.Millisecond)
			}
			return want, nil
		},
	)
	if err != nil {
		close(paused.release)
		t.Fatal(err)
	}
	select {
	case <-paused.entered:
	case <-time.After(time.Second):
		close(paused.release)
		t.Fatal("third acceptance was not dispatched")
	}
	clear(result)
	close(paused.release)
	var got []byte
	select {
	case got = <-paused.observed:
	case <-time.After(time.Second):
		t.Fatal("third acceptance did not inspect its payload")
	}
	if !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"caller mutation altered pending same-ballot acceptance: got %q, want %q",
			got,
			want,
		)
	}
	p.Close()
	if got := read(
		t,
		proposer(
			t,
			peers(acceptors),
		),
	); !bytes.Equal(
		got,
		want,
	) {
		t.Fatalf(
			"caller mutation corrupted chosen state: got %q, want %q",
			got,
			want,
		)
	}
}
