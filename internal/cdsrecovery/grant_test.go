package cdsrecovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSealedGrantBindsAuthorityProcessAndIdentity(t *testing.T) {
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{ClusterID: "one", ConfigSHA256: strings.Repeat("ab", 32), Prefix: "one/wal"}
	r, err := NewRecipient(id)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{42}, 32)
	g, err := seal(r.Request(), Material{Key: key, AllowGenesis: true}, signer)
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.Open(*g, pub)
	if err != nil || !bytes.Equal(m.Key, key) || !m.AllowGenesis {
		t.Fatalf("open: %+v", err)
	}
	clear(m.Key)
	// A copied request must not change the recipient's private identity.
	q := r.Request()
	q.Nonce[0] ^= 1
	q.PublicKey[0] ^= 1
	if _, err := r.Open(*g, pub); err != nil {
		t.Fatal(err)
	}
	for name, identity := range map[string]Identity{
		"new process":   id,
		"other cluster": {ClusterID: "two", ConfigSHA256: id.ConfigSHA256, Prefix: id.Prefix},
		"other config":  {ClusterID: id.ClusterID, ConfigSHA256: strings.Repeat("cd", 32), Prefix: id.Prefix},
		"other prefix":  {ClusterID: id.ClusterID, ConfigSHA256: id.ConfigSHA256, Prefix: "two/wal"},
	} {
		t.Run(name, func(t *testing.T) {
			other, err := NewRecipient(identity)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := other.Open(*g, pub); err == nil {
				t.Fatal("grant crossed recipient boundary")
			}
		})
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := r.Open(*g, other); err == nil {
		t.Fatal("accepted another authority")
	}
	for name, change := range map[string]func(*Grant){
		"signature":  func(g *Grant) { g.Signature[0] ^= 1 },
		"request":    func(g *Grant) { g.RequestHash[0] ^= 1 },
		"kem":        func(g *Grant) { g.KEM[0] ^= 1 },
		"ciphertext": func(g *Grant) { g.Record.CT[0] ^= 1 },
		"sequence":   func(g *Grant) { g.Record.Seq++ },
		"oversize":   func(g *Grant) { g.Record.CT = make([]byte, 257) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := g.Clone()
			change(bad)
			if _, err := r.Open(*bad, pub); err == nil {
				t.Fatal("accepted modified grant")
			}
		})
	}
	// Even an authority-signed transplant cannot bind ciphertext to a different
	// request: the KEM recipient and channel transcript are authenticated too.
	newProcess, _ := NewRecipient(id)
	transplant := g.Clone()
	transplant.RequestHash = requestHash(newProcess.Request())
	transplant.Signature = ed25519.Sign(signer, signedBytes(*transplant))
	if _, err := newProcess.Open(*transplant, pub); err == nil {
		t.Fatal("accepted ciphertext transplant")
	}
	// Recovery is the default. Redelivery in the same process is intentional:
	// it supports retrying an ambiguous provisioning response, not a new write.
	g, err = seal(r.Request(), Material{Key: key}, signer)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		m, err := r.Open(*g, pub)
		if err != nil || m.AllowGenesis || !bytes.Equal(m.Key, key) {
			t.Fatal("recovery grant changed")
		}
		clear(m.Key)
	}
}
