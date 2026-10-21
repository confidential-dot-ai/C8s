package shamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitCombine(t *testing.T) {
	secret := make([]byte, 241)
	_, _ = rand.Read(secret)
	shares, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Every 3-subset recovers it; with 4 and 5 too.
	for a := 0; a < 5; a++ {
		for b := a + 1; b < 5; b++ {
			for c := b + 1; c < 5; c++ {
				got, err := Combine([]Share{shares[a], shares[c], shares[b]})
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("shares %d,%d,%d: %v", a, b, c, err)
				}
			}
		}
	}
	if got, _ := Combine(shares); !bytes.Equal(got, secret) {
		t.Fatal("all five")
	}
	// Two of a 3-threshold give a wrong value, not the secret.
	if got, _ := Combine(shares[:2]); bytes.Equal(got, secret) {
		t.Fatal("two shares of three recovered the secret")
	}
	for _, s := range shares {
		if bytes.Equal(s.Y, secret) {
			t.Fatal("a share is the secret")
		}
	}
}

func TestRefusals(t *testing.T) {
	for _, c := range []struct{ n, k int }{{3, 1}, {2, 3}, {256, 3}} {
		if _, err := Split([]byte{1}, c.n, c.k); err == nil {
			t.Fatalf("n=%d k=%d accepted", c.n, c.k)
		}
	}
	if _, err := Split(nil, 3, 2); err == nil {
		t.Fatal("empty secret")
	}
	s, _ := Split([]byte{1, 2}, 3, 2)
	for name, in := range map[string][]Share{
		"one":       s[:1],
		"duplicate": {s[0], s[0]},
		"zero x":    {{X: 0, Y: []byte{1, 2}}, s[1]},
		"lengths":   {s[0], {X: 9, Y: []byte{1}}},
	} {
		if _, err := Combine(in); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestField(t *testing.T) {
	for a := 1; a < 256; a++ {
		if mul(byte(a), div(1, byte(a))) != 1 {
			t.Fatalf("no inverse for %d", a)
		}
	}
}
