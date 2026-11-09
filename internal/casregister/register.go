// Package casregister implements a fixed three-member classic CASPaxos register.
// See README.md for the trusted-storage and correct-proposer assumptions.
package casregister

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
)

const MaxValueBytes = 64 << 20

var (
	ErrUnavailable  = errors.New("current register unavailable before acceptance")
	ErrUnknown      = errors.New("current register acceptance outcome unknown")
	ErrBusy         = errors.New("current register mailbox full")
	ErrClosed       = errors.New("current register closed")
	ErrInvalid      = errors.New("invalid current register request or state")
	ErrEquivocation = errors.New("different values proposed at the same ballot")
)

type Ballot struct {
	Round uint64
	Owner [32]byte
}

func (b Ballot) Compare(other Ballot) int {
	if b.Round < other.Round {
		return -1
	}
	if b.Round > other.Round {
		return 1
	}
	return bytes.Compare(
		b.Owner[:],
		other.Owner[:],
	)
}

func (b Ballot) valid() bool {
	return b.Round > 0 && b.Owner != [32]byte{}
}

func (b Ballot) encode() []byte {
	out := make(
		[]byte,
		40,
	)
	binary.BigEndian.PutUint64(
		out,
		b.Round,
	)
	copy(
		out[8:],
		b.Owner[:],
	)
	return out
}

func decodeBallot(data []byte) (Ballot, error) {
	if len(data) != 40 {
		return Ballot{}, ErrInvalid
	}
	b := Ballot{Round: binary.BigEndian.Uint64(data)}
	copy(
		b.Owner[:],
		data[8:],
	)
	if b != (Ballot{}) && !b.valid() {
		return Ballot{}, ErrInvalid
	}
	return b, nil
}

type Promise struct {
	Accepted Ballot
	Value    []byte
}

type Preempted struct {
	Promise Ballot
}

func (e *Preempted) Error() string { return "current register ballot preempted" }

// Peer implementations must honor context cancellation and preserve member
// identity. This package supplies local calls, not authenticated network RPC.
type Peer interface {
	ID() string
	Prepare(
		context.Context,
		string,
		Ballot,
	) (Promise, error)
	Accept(
		context.Context,
		string,
		Ballot,
		[]byte,
	) error
}
