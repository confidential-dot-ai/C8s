// Package lthash is a homomorphic multiset hash: LtHash16 (Bellare and
// Micciancio, "A New Paradigm for Collision-free Hashing", 1997; parameters
// of Lewi et al., "Securing Update Propagation with Homomorphic Hashing",
// 2019). Adding and removing elements in any order gives the same hash as
// hashing the final set once, so a store can keep the digest of its whole
// content current at the cost of the rows each write changes.
package lthash

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
)

const lanes = 1024

// Hash is a multiset of elements. The zero value is the empty set.
type Hash struct{ l [lanes]uint16 }

// element expands a collision-resistant digest of one element to the lanes.
func element(d [32]byte) *Hash {
	var buf [2 * lanes]byte
	x := sha3.NewSHAKE128()
	_, _ = x.Write(d[:])
	_, _ = x.Read(buf[:])
	e := new(Hash)
	for i := range e.l {
		e.l[i] = binary.LittleEndian.Uint16(buf[2*i:])
	}
	return e
}

// Add puts the element whose SHA-256 is d into the set.
func (h *Hash) Add(d [32]byte) { h.Combine(element(d)) }

// Remove takes the element whose SHA-256 is d out of the set.
func (h *Hash) Remove(d [32]byte) {
	e := element(d)
	for i := range h.l {
		h.l[i] -= e.l[i]
	}
}

// Combine adds every element of o to h.
func (h *Hash) Combine(o *Hash) {
	for i := range h.l {
		h.l[i] += o.l[i]
	}
}

// Sum names the set in 32 bytes.
func (h *Hash) Sum() [32]byte {
	var buf [2 * lanes]byte
	for i, v := range h.l {
		binary.LittleEndian.PutUint16(buf[2*i:], v)
	}
	return sha256.Sum256(buf[:])
}
