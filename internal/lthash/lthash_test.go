package lthash

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"math/rand/v2"
	"strconv"
	"testing"
)

func el(i int) [32]byte { return sha256.Sum256([]byte(strconv.Itoa(i))) }

// The hash depends only on the final multiset, not on the order of changes.
func TestOrderAndRemoval(t *testing.T) {
	var a, b Hash
	for i := range 100 {
		a.Add(el(i))
	}
	for i := 199; i >= 0; i-- {
		b.Add(el(i))
	}
	for i := 100; i < 200; i++ {
		b.Remove(el(i))
	}
	if a.Sum() != b.Sum() {
		t.Fatal("same set, different hash")
	}
	b.Remove(el(5))
	if a.Sum() == b.Sum() {
		t.Fatal("different sets, same hash")
	}
	var empty Hash
	b.Add(el(5))
	for i := range 100 {
		b.Remove(el(i))
	}
	if b.Sum() != empty.Sum() {
		t.Fatal("emptied set differs from the empty set")
	}
}

// refElement is the expansion as first written (a new Hash per element):
// Add and Remove must give the same lanes.
func refElement(d [32]byte) *Hash {
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

func TestSameDigestAsReference(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		var got, want Hash
		for range r.IntN(200) {
			d := el(r.IntN(64))
			if r.IntN(3) == 0 {
				got.Remove(d)
				e := refElement(d)
				for i := range want.l {
					want.l[i] -= e.l[i]
				}
			} else {
				got.Add(d)
				want.Combine(refElement(d))
			}
		}
		if got.Sum() != want.Sum() {
			t.Fatal("digest differs from the reference expansion")
		}
	}
}

func BenchmarkAdd(b *testing.B) {
	var h Hash
	d := el(1)
	for b.Loop() {
		h.Add(d)
	}
}
