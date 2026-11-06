// Package lthash is a homomorphic multiset hash: LtHash16 (Bellare and
// Micciancio, "A New Paradigm for Collision-free Hashing", 1997; parameters
// of Lewi et al., "Securing Update Propagation with Homomorphic Hashing",
// 2019). Adding and removing elements in any order gives the same hash as
// hashing the final set once, so a store can keep the digest of everything it
// holds current at the cost of the entries each write changes.
package lthash

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"io"
)

// Parameter set of Lewi et al.: 1024 counters of 16 bits.
const lanes = 1024

// The zero value is the empty set.
type Hash struct {
	l [lanes]uint16
}

// Element names a multiset element by its length-prefixed fields, so no two
// splits of the same bytes name one element. Every store that digests entries
// of its own uses it.
func Element(fields ...[]byte) [32]byte {
	h := sha256.New()
	var prefix [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(prefix[:], uint64(len(f)))
		h.Write(prefix[:])
		h.Write(f)
	}
	return [32]byte(h.Sum(nil))
}

func expand(d [32]byte, buf *[2 * lanes]byte) {
	stream := sha3.NewSHAKE128()
	_, _ = stream.Write(d[:])
	// SHAKE128 never ends, so buf always fills.
	_, _ = io.ReadFull(stream, buf[:])
}

func (h *Hash) Add(d [32]byte) {
	var buf [2 * lanes]byte
	expand(d, &buf)
	for i := range h.l {
		h.l[i] += binary.LittleEndian.Uint16(buf[2*i:])
	}
}

func (h *Hash) Remove(d [32]byte) {
	var buf [2 * lanes]byte
	expand(d, &buf)
	for i := range h.l {
		h.l[i] -= binary.LittleEndian.Uint16(buf[2*i:])
	}
}

func (h *Hash) Combine(o *Hash) {
	for i := range h.l {
		h.l[i] += o.l[i]
	}
}

func (h *Hash) Sum() [32]byte {
	counters := h.counters()
	return sha256.Sum256(counters[:])
}

func (h *Hash) counters() [2 * lanes]byte {
	var counters [2 * lanes]byte
	for i, v := range h.l {
		binary.LittleEndian.PutUint16(counters[2*i:], v)
	}
	return counters
}
