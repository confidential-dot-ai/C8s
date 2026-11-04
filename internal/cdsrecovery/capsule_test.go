package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func wrappingFixture(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(b) })
	return b
}

type capsuleProcessInput struct {
	Identity    Identity
	Record      []byte
	Capsule     Capsule
	WrappingKey []byte // SOFTWARE hardware fixture, provided only over stdin.
	Verifier    string
	Origin      string
}

// Each invocation starts a fresh process containing no previous authority
// keys. Only the simulated external hardware wrapping key survives in parent
// memory. This is process recovery evidence, not hardware-custody evidence.
func TestSealedAuthorityProcessHelper(t *testing.T) {
	if os.Getenv("CDS_CAPSULE_TEST_HELPER") != "1" {
		return
	}
	var in capsuleProcessInput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		os.Exit(2)
	}
	a, err := RestoreSealedAuthority(context.Background(), in.Identity, in.Record, in.Capsule, in.WrappingKey, in.Verifier)
	clear(in.WrappingKey)
	if err != nil {
		os.Exit(3)
	}
	grant, err := a.Release(context.Background(), in.Origin)
	a.Close()
	if err != nil || json.NewEncoder(os.Stdout).Encode(grant) != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

func restoreProcess(t *testing.T, in capsuleProcessInput) (*Grant, error) {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSealedAuthorityProcessHelper$")
	cmd.Env = append(os.Environ(), "CDS_CAPSULE_TEST_HELPER=1")
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var grant Grant
	return &grant, json.Unmarshal(out, &grant)
}

func TestCapsulesRecoverAfterAuthorityProcessAndOneAnchorLoss(t *testing.T) {
	f := newAuthorityFixture(t, "sealed")
	rootA, rootB := wrappingFixture(t), wrappingFixture(t)
	a, err := SealAuthority(f.identity, f.record, f.key, f.signer, rootA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealAuthority(f.identity, f.record, f.key, f.signer, rootB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("independent wrappers produced identical ciphertext")
	}
	public := bytes.Clone(f.signer.Public().(ed25519.PublicKey))
	keyHash := sha256.Sum256(f.key)
	// Keep no plaintext WAL/signing keys in the parent after sealing.
	clear(f.key)
	clear(f.signer)
	in := capsuleProcessInput{Identity: f.identity, Record: f.record, Capsule: a, WrappingKey: rootA, Verifier: f.verifier.URL(), Origin: f.origin}
	for round := range 2 {
		if round == 1 {
			clear(rootA) // The first simulated anchor is permanently unavailable.
			in.Capsule, in.WrappingKey = b, rootB
		}
		r, err := NewRecipient(f.identity)
		if err != nil {
			t.Fatal(err)
		}
		f.recipient.Store(r)
		grant, err := restoreProcess(t, in)
		if err != nil {
			t.Fatal("fresh authority process could not recover:", err)
		}
		m, err := r.Open(*grant, public)
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(m.Key)
		clear(m.Key)
		if got != keyHash || m.AllowGenesis {
			t.Fatal("recovery changed key or authorized replacement genesis")
		}
	}
	// No remaining anchor: ciphertext cannot silently create new custody keys.
	clear(rootB)
	if _, err := restoreProcess(t, in); err == nil {
		t.Fatal("recovered after losing every simulated anchor")
	}
}

func TestCapsuleRefusesScopeEnrollmentAndWrappingChanges(t *testing.T) {
	f := newAuthorityFixture(t, "bound")
	root := wrappingFixture(t)
	capsule, err := SealAuthority(f.identity, f.record, f.key, f.signer, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"other root", "other cluster", "other config", "other prefix", "edited enrollment", "truncated", "tampered", "version"} {
		t.Run(name, func(t *testing.T) {
			identity, record, key, c := f.identity, bytes.Clone(f.record), bytes.Clone(root), capsule
			c.Ciphertext = bytes.Clone(c.Ciphertext)
			defer clear(key)
			switch name {
			case "other root":
				key[0] ^= 1
			case "other cluster":
				identity.ClusterID = "another"
			case "other config":
				identity.ConfigSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			case "other prefix":
				identity.Prefix = "elsewhere"
			case "edited enrollment":
				record = append(record, ' ')
			case "truncated":
				c.Ciphertext = c.Ciphertext[:len(c.Ciphertext)-1]
			case "tampered":
				c.Ciphertext[0] ^= 1
			case "version":
				c.Version++
			}
			a, err := RestoreSealedAuthority(t.Context(), identity, record, c, key, f.verifier.URL())
			if err == nil {
				a.Close()
				t.Fatal("accepted changed binding")
			}
		})
	}
}

// Counterexample, not a retirement acceptance test. A newly signed enrollment
// that accepts only v2 does not erase v1's old capsule or signed enrollment.
// Replaying both still restores v1's release authority. A current-policy gate
// must therefore precede release; static sealing cannot supply that gate.
func TestCapsuleAloneDoesNotRetireOldEnrollment(t *testing.T) {
	f := newAuthorityFixture(t, "retirement")
	root := wrappingFixture(t)
	old, err := SealAuthority(f.identity, f.record, f.key, f.signer, root)
	if err != nil {
		t.Fatal(err)
	}
	var next registration
	if err := json.Unmarshal(f.record, &next); err != nil {
		t.Fatal(err)
	}
	// Change the approved image independently of representation in the fixture.
	var pins map[string]any
	if err := json.Unmarshal(next.Policy.Pins, &pins); err != nil {
		t.Fatal(err)
	}
	measurements := pins["measurements"].([]any)
	measurements[0].(map[string]any)["measurement"] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	next.Policy.Pins, err = json.Marshal(pins)
	if err != nil {
		t.Fatal(err)
	}
	next.Signature = ed25519.Sign(f.signer, registrationBytes(next))
	newRecord, _ := json.Marshal(next)
	current, err := NewAuthority(t.Context(), f.identity, newRecord, f.key, f.signer, f.verifier.URL())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.Release(t.Context(), f.origin); err == nil {
		t.Fatal("new enrollment accepted retired image")
	}
	approved := f.verdict
	approved.Claims.LaunchDigest = strings.Repeat("cc", 48)
	f.verifier.SetVerdict(approved)
	replacement, err := NewRecipient(f.identity)
	if err != nil {
		t.Fatal(err)
	}
	f.recipient.Store(replacement)
	if f.readGrant(t, current).AllowGenesis {
		t.Fatal("approved upgrade received genesis authority")
	}
	f.verifier.SetVerdict(f.verdict)
	current.Close()
	if a, err := RestoreSealedAuthority(t.Context(), f.identity, newRecord, old, root, f.verifier.URL()); err == nil {
		a.Close()
		t.Fatal("old capsule accepted as the new enrollment")
	}
	replayed, err := RestoreSealedAuthority(t.Context(), f.identity, f.record, old, root, f.verifier.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer replayed.Close()
	f.readGrant(t, replayed) // Demonstrates the missing freshness/retirement gate.
}

func TestCapsuleRefusesUnrecoverableMaterial(t *testing.T) {
	f := newAuthorityFixture(t, "invalid")
	root := wrappingFixture(t)
	for _, change := range []string{"wrapping key", "WAL key", "registration", "signing seed"} {
		t.Run(change, func(t *testing.T) {
			wrap, key, record, signer := root, bytes.Clone(f.key), bytes.Clone(f.record), bytes.Clone(f.signer)
			defer clear(key)
			defer clear(signer)
			switch change {
			case "wrapping key":
				wrap = wrap[:31]
			case "WAL key":
				key[0] ^= 1
			case "registration":
				record = nil
			case "signing seed":
				signer[0] ^= 1 // Public half still verifies the record.
			}
			if _, err := SealAuthority(f.identity, record, key, signer, wrap); err == nil {
				t.Fatal("sealed unrecoverable material")
			}
		})
	}
}
