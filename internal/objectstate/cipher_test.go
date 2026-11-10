package objectstate

import (
	"bytes"
	"errors"
	"testing"
)

func TestCipherBindsClusterAndStorage(t *testing.T) {
	key := bytes.Repeat(
		[]byte{7},
		32,
	)
	sealed, err := NewCipher(
		key,
		[]byte("cluster-a/storage-a"),
		1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	first, err := sealed.Seal([]byte("synthetic state"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealed.Seal([]byte("synthetic state"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(
		first,
		second,
	) {
		t.Fatal("repeated content reused ciphertext and could permit ETag ABA")
	}
	plain, err := sealed.Open(first)
	if err != nil || string(plain) != "synthetic state" {
		t.Fatalf(
			"round trip: %q, %v",
			plain,
			err,
		)
	}
	for _, domain := range []string{
		"cluster-b/storage-a",
		"cluster-a/storage-b",
	} {
		other, err := NewCipher(
			key,
			[]byte(domain),
			1024,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Open(first); err == nil {
			t.Fatal("accepted another cluster or storage authority")
		}
	}
	for i := range first {
		modified := bytes.Clone(first)
		modified[i] ^= 1
		if _, err := sealed.Open(modified); err == nil {
			t.Fatalf(
				"accepted modified ciphertext byte %d",
				i,
			)
		}
	}
}

func TestCipherBoundsEncryptedAndPlainState(t *testing.T) {
	c, err := NewCipher(
		bytes.Repeat(
			[]byte{9},
			32,
		),
		[]byte("test"),
		1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(make(
		[]byte,
		1024,
	)); !errors.Is(
		err,
		ErrTooLarge,
	) {
		t.Fatalf(
			"oversized plaintext: %v",
			err,
		)
	}
	if _, err := c.Open(make(
		[]byte,
		1025,
	)); !errors.Is(
		err,
		ErrTooLarge,
	) {
		t.Fatalf(
			"oversized ciphertext: %v",
			err,
		)
	}
	for n := 0; n < 41; n++ {
		if _, err := c.Open(make(
			[]byte,
			n,
		)); err == nil {
			t.Fatalf(
				"accepted truncated ciphertext length %d",
				n,
			)
		}
	}
}
