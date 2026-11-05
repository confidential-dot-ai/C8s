package snpaccept

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCustodyCopiesSurviveLossOfOneIndependentRoot(t *testing.T) {
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	wrap := bytes.Repeat([]byte{19}, 32)
	launch := []byte("approved completed launch; software protocol test only")
	roots := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
	var copies []*CustodyCopy
	for _, root := range roots {
		c, err := sealCopy(root, launch, Parameters{GuestSVN: 3, TCB: 4}, signer, wrap)
		if err != nil {
			t.Fatal(err)
		}
		copies = append(copies, c)
	}
	clear(roots[0])
	if key, material, err := openCopy(roots[0], launch, *copies[0], public); err == nil {
		clear(key)
		clear(material)
		t.Fatal("lost root recovered its capsule")
	}
	key, material, err := openCopy(roots[1], launch, *copies[1], public)
	defer clear(key)
	defer clear(material)
	if err != nil || !bytes.Equal(key, signer) || !bytes.Equal(material, wrap) {
		t.Fatalf("surviving independent copy changed authority: %v", err)
	}
	if key, material, err := openCopy(roots[1], launch, *copies[0], public); err == nil {
		clear(key)
		clear(material)
		t.Fatal("another chip's capsule opened without enrollment")
	}
}

func TestCustodyCopyBindsImageContextAuthorityAndParameters(t *testing.T) {
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	for _, scenario := range []string{"launch", "root", "authority", "guest-svn", "tcb", "version", "ciphertext", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			root, launch := bytes.Repeat([]byte{7}, 32), []byte("approved exact launch")
			c, err := sealCopy(root, launch, Parameters{GuestSVN: 1, TCB: 2}, signer, bytes.Repeat([]byte{8}, 32))
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(public)
			switch scenario {
			case "launch":
				launch[0] ^= 1
			case "root":
				root[0] ^= 1
			case "authority":
				want[0] ^= 1
			case "guest-svn":
				c.Parameters.GuestSVN++
			case "tcb":
				c.Parameters.TCB++
			case "version":
				c.Version++
			case "ciphertext":
				c.Ciphertext[0] ^= 1
			case "truncated":
				c.Ciphertext = c.Ciphertext[:32]
			}
			key, material, err := openCopy(root, launch, *c, ed25519.PublicKey(want))
			clear(key)
			clear(material)
			if err == nil {
				t.Fatal("substituted custody copy accepted")
			}
		})
	}
}
