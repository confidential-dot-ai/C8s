package cdsha

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func policyVariants(p FSMPolicy) map[string]FSMPolicy {
	variants := map[string]FSMPolicy{"missing": {}, "unknown": p}
	unknown := p
	unknown.Version++
	variants["unknown"] = unknown
	ttl := p
	ttl.LedgerTTLNS++
	variants["ledger ttl"] = ttl
	max := p
	max.LedgerMax++
	variants["ledger max"] = max
	paths := p
	paths.SecretsMaxPaths++
	variants["secret paths"] = paths
	holder := p
	holder.SecretsMaxPerHolder++
	variants["secret holder"] = holder
	value := p
	value.SecretsMaxValue++
	variants["secret value"] = value
	return variants
}

func TestPolicyRejectsBeforeApply(t *testing.T) {
	for name, policy := range policyVariants(newTestFSM(t, nil).LocalPolicy()) {
		t.Run(name, func(t *testing.T) {
			f := newTestFSM(t, nil)
			f.core.Policy = policy
			result := applyAt(f, 1, Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/blocked", Value: []byte("value")}})
			err, ok := result.(error)
			if !ok || !errors.Is(err, ErrPolicy) || f.Stuck() == "" {
				t.Fatalf("result %v; stuck %q", result, f.Stuck())
			}
			if _, err := f.secrets.Get(context.Background(), "/blocked"); !errors.Is(err, secrets.ErrNotFound) {
				t.Fatalf("store changed: %v", err)
			}
		})
	}
}

func TestPolicyRestorePreservesAndRejectsBeforeReplacement(t *testing.T) {
	source := newTestFSM(t, nil)
	source.core.Policy = source.LocalPolicy()
	if _, err := source.secrets.Put(context.Background(), "/incoming", []byte("new")); err != nil {
		t.Fatal(err)
	}
	dest := newTestFSM(t, nil)
	if err := restoreCopy(t, source, dest); err != nil {
		t.Fatal(err)
	}
	if dest.Core().Policy != source.Core().Policy {
		t.Fatal("snapshot lost policy")
	}
	for name, policy := range policyVariants(source.LocalPolicy()) {
		t.Run(name, func(t *testing.T) {
			target := newTestFSM(t, nil)
			target.core.Policy = target.LocalPolicy()
			if _, err := target.secrets.Put(context.Background(), "/kept", []byte("old")); err != nil {
				t.Fatal(err)
			}
			before := target.Core()
			source.core.Policy = policy
			if err := restoreCopy(t, source, target); !errors.Is(err, ErrPolicy) {
				t.Fatalf("restore: %v", err)
			}
			if target.Core().Policy != before.Policy {
				t.Fatal("core replaced")
			}
			if got, err := target.secrets.Get(context.Background(), "/kept"); err != nil || string(got) != "old" {
				t.Fatalf("old state lost: %q %v", got, err)
			}
			if _, err := target.secrets.Get(context.Background(), "/incoming"); !errors.Is(err, secrets.ErrNotFound) {
				t.Fatal("incoming state installed")
			}
		})
	}
}

func TestGenesisPersistsExactPolicy(t *testing.T) {
	key, pub := operatorKey(t)
	ca := mustCA(t)
	der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	makeEntry := func(p FSMPolicy) DecreeEntry {
		return DecreeEntry{Policy: p, Decree: signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"}), AtMS: time.Now().UnixMilli(), Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: der}
	}
	f := newTestFSM(t, pub)
	f.core.Policy = FSMPolicy{}
	de := makeEntry(f.LocalPolicy())
	if got := applyAt(f, 1, Entry{Kind: KindDecree, Decree: &de}).(DecreeResult); got.Err != "" {
		t.Fatal(got.Err)
	}
	if f.Core().Policy != de.Policy {
		t.Fatal("Genesis lost policy")
	}
	for name, policy := range policyVariants(f.LocalPolicy()) {
		t.Run(name, func(t *testing.T) {
			target := newTestFSM(t, pub)
			target.core.Policy = FSMPolicy{}
			de := makeEntry(policy)
			got := applyAt(target, 1, Entry{Kind: KindDecree, Decree: &de}).(DecreeResult)
			if got.Err == "" || target.Core().Joined() || target.Core().Policy != (FSMPolicy{}) {
				t.Fatalf("invalid Genesis applied: %+v", got)
			}
		})
	}
}

func TestPolicyEmptyClonesRetainLocalSettings(t *testing.T) {
	f := newTestFSM(t, nil)
	al, _, _ := testStores(t)
	clone := NewFSM(f.Core(), al, f.secrets.EmptyClone(), f.ledger.EmptyClone())
	if clone.LocalPolicy() != f.LocalPolicy() {
		t.Fatal("clone changed local policy")
	}
	f.core.Policy = f.LocalPolicy()
	bad := f.core.Policy
	bad.LedgerTTLNS++
	clone.core = f.Core()
	clone.core.Policy = bad
	if !errors.Is(clone.ValidatePolicy(clone.Core().Policy), ErrPolicy) {
		t.Fatal("clone discarded persisted reference")
	}
}
