package lthash

import (
	"crypto/sha256"
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

func BenchmarkAdd(b *testing.B) {
	var h Hash
	d := el(1)
	for b.Loop() {
		h.Add(d)
	}
}
