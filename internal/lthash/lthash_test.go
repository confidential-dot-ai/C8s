package lthash

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"math/rand/v2"
	"strconv"
	"testing"
)

func el(i int) [32]byte {
	return sha256.Sum256([]byte(strconv.Itoa(i)))
}

func TestTheHashIsTheSetAndNotTheOrder(t *testing.T) {
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
		t.Fatal("the same set in another order has another hash")
	}
	b.Remove(el(5))
	if a.Sum() == b.Sum() {
		t.Fatal("a set an element short has the same hash")
	}
	b.Add(el(5))
	for i := range 100 {
		b.Remove(el(i))
	}
	var empty Hash
	if b.Sum() != empty.Sum() {
		t.Fatal("an emptied set differs from the empty set")
	}
}

// The hash as its definition reads, not as Add builds it.
func sumOfElementLanes(elements [][32]byte) Hash {
	var h Hash
	for _, d := range elements {
		var buf [2 * lanes]byte
		x := sha3.NewSHAKE128()
		_, _ = x.Write(d[:])
		_, _ = x.Read(buf[:])
		for i := range h.l {
			h.l[i] += binary.LittleEndian.Uint16(buf[2*i:])
		}
	}
	return h
}

func TestTheHashAccumulatesTheCountersOfItsElements(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		var got Hash
		var held [][32]byte
		for range r.IntN(200) {
			d := el(r.IntN(64))
			if r.IntN(3) == 0 && len(held) > 0 {
				at := r.IntN(len(held))
				got.Remove(held[at])
				held = append(held[:at], held[at+1:]...)
				continue
			}
			got.Add(d)
			held = append(held, d)
		}
		if want := sumOfElementLanes(held); got.Sum() != want.Sum() {
			t.Fatalf("the hash of %d elements differs from the sum of their lanes", len(held))
		}
	}
}

func TestAnElementIsItsFieldsAndTheirLengths(t *testing.T) {
	cases := map[string][][]byte{
		"two fields":       {[]byte("ab"), []byte("c")},
		"split elsewhere":  {[]byte("a"), []byte("bc")},
		"one field":        {[]byte("abc")},
		"an empty field":   {[]byte("abc"), {}},
		"a trailing field": {[]byte("abc"), []byte("d")},
	}
	seen := map[[32]byte]string{}
	for name, fields := range cases {
		d := Element(fields...)
		if first, ok := seen[d]; ok {
			t.Errorf("%s and %s name one element", first, name)
		}
		seen[d] = name
	}
}

func BenchmarkAdd(b *testing.B) {
	var h Hash
	d := el(1)
	for b.Loop() {
		h.Add(d)
	}
}
