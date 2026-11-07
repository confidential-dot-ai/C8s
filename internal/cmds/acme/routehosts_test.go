package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestUnionDomains(t *testing.T) {
	launch := []string{"lb.example.com", "infer.lb.example.com"}
	for _, tc := range []struct {
		name   string
		extras []string
		want   []string
	}{
		{"no extras", nil, launch},
		{"adds after launch", []string{"b.example.com", "a.example.com"}, append(slices.Clone(launch), "b.example.com", "a.example.com")},
		{"launch name once", []string{"lb.example.com", "a.example.com"}, append(slices.Clone(launch), "a.example.com")},
		{"repeated extra once", []string{"a.example.com", "a.example.com"}, append(slices.Clone(launch), "a.example.com")},
		{"skips non-certificate names", []string{"*.example.com", "192.0.2.1", "UPPER.example.com", "a.example.com"}, append(slices.Clone(launch), "a.example.com")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unionDomains(launch, tc.extras, slog.Default()); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("caps at the CA limit", func(t *testing.T) {
		var extras []string
		for i := range 2 * maxNames {
			extras = append(extras, fmt.Sprintf("h%d.example.com", i))
		}
		got := unionDomains(launch, extras, slog.Default())
		if len(got) != maxNames || !slices.Equal(got[:2], launch) {
			t.Fatalf("got %d names starting %v", len(got), got[:2])
		}
	})
}

func TestWantedReadsRouteHosts(t *testing.T) {
	dir := t.TempDir()
	mgr := newManager("", "", t.TempDir(), t.TempDir(), []string{"lb.example.com"}, slog.Default())
	mgr.extraDomainsFile = filepath.Join(dir, "hosts")

	if got := mgr.wanted(); !slices.Equal(got, []string{"lb.example.com"}) {
		t.Fatalf("before the first manifest: %v", got)
	}
	writeHosts(t, mgr, "app.example.com\n")
	if got := mgr.wanted(); !slices.Equal(got, []string{"lb.example.com", "app.example.com"}) {
		t.Fatalf("with a route host: %v", got)
	}
	// A read error keeps the last set rather than dropping names.
	if err := os.Remove(mgr.extraDomainsFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mgr.extraDomainsFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := mgr.wanted(); !slices.Equal(got, []string{"lb.example.com", "app.example.com"}) {
		t.Fatalf("after a read error: %v", got)
	}
}

func writeHosts(t *testing.T, mgr *manager, data string) {
	t.Helper()
	if err := os.WriteFile(mgr.extraDomainsFile, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A host the applied manifest adds is issued for, verified and only then
// served; a failed issuance keeps serving the old set; a removed host is
// dropped by re-issuing without it.
func TestRouteHostIssueThenSwap(t *testing.T) {
	ca := newTestCA(t)
	launch := []string{"lb.example.com"}
	mgr := newTestManager(t, ca, launch)
	mgr.extraDomainsFile = filepath.Join(t.TempDir(), "hosts")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if !mgr.ensure(ctx) {
		t.Fatal("launch issuance failed")
	}
	assertSANs(t, mgr, launch)
	served, _ := os.ReadFile(mgr.certPath())

	writeHosts(t, mgr, "app.example.com\n")
	if !mgr.needsIssue() {
		t.Fatal("a new route host does not ask for issuance")
	}
	// The CA is unreachable: the served certificate stays.
	good, goodURL := mgr.client, mgr.directoryURL
	mgr.client, mgr.directoryURL = nil, "http://127.0.0.1:1/dir"
	if mgr.ensure(ctx) {
		t.Fatal("ensure reported success against an unreachable CA")
	}
	if after, _ := os.ReadFile(mgr.certPath()); !bytes.Equal(after, served) {
		t.Fatal("a failed issuance replaced the served certificate")
	}
	mgr.client, mgr.directoryURL = good, goodURL

	if !mgr.ensure(ctx) {
		t.Fatal("issuance with the route host failed")
	}
	assertSANs(t, mgr, []string{"lb.example.com", "app.example.com"})

	writeHosts(t, mgr, "")
	if !mgr.ensure(ctx) {
		t.Fatal("issuance after removal failed")
	}
	assertSANs(t, mgr, launch)
}

func assertSANs(t *testing.T, mgr *manager, want []string) {
	t.Helper()
	leaf, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if !sameDomainSet(leaf.DNSNames, want) {
		t.Fatalf("served SANs = %v, want %v", leaf.DNSNames, want)
	}
}

func TestVerifyIssued(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	names := []string{"lb.example.com", "app.example.com"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(signer *testCA, dnsNames []string, k *ecdsa.PrivateKey) [][]byte {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: dnsNames}, k)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(signer.sign(t, csr))
		return [][]byte{block.Bytes, ca.cert.Raw}
	}
	now := time.Now()
	if err := verifyIssued(issue(ca, names, key), key, names, now); err != nil {
		t.Fatalf("good chain: %v", err)
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tc := range map[string]struct {
		chain [][]byte
		now   time.Time
	}{
		"empty":        {nil, now},
		"wrong key":    {issue(ca, names, otherKey), now},
		"missing name": {issue(ca, names[:1], key), now},
		"wrong issuer": {issue(other, names, key), now},
		"expired":      {issue(ca, names, key), now.Add(365 * 24 * time.Hour)},
	} {
		if err := verifyIssued(tc.chain, key, names, tc.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
