package workloadclaims

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The transport of a real callback client must stop reusing a connection when
// its node policy changes. Testing only its TLS callback misses this path.
func TestDigestsClientRetiresEstablishedInventoryConnections(t *testing.T) {
	digest := bytes.Repeat([]byte{0x11}, refvalues.DigestSize)
	pins := &inventoryPins{}
	pins.replace(digest)
	verifier := mockapi.New(t)
	verifier.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(digest)))
	key, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := armtls.CreateAttestedCert(key, &armtls.Attestation{
		Family: armtls.TEETypeSEVSNP,
		Report: make([]byte, armtls.SNPReportSize),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var mu sync.Mutex
	var clientCertificates [][]byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "no callback client identity", http.StatusForbidden)
			return
		}
		mu.Lock()
		clientCertificates = append(clientCertificates, bytes.Clone(r.TLS.PeerCertificates[0].Raw))
		mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	var attestations atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	client, err := NewDigestsClient(ctx, DigestsClientConfig{
		Platform: "sev-snp",
		AttestFunc: func(context.Context, string) (string, error) {
			attestations.Add(1)
			return string(make([]byte, armtls.SNPReportSize)), nil
		},
		AttestationAPIURL: verifier.URL(),
		NodeImages:        pins,
		Timeout:           3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Timeout != 3*time.Second {
		t.Fatal("callback timeout changed")
	}
	request := func() (bool, error) {
		t.Helper()
		reused := false
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, server.URL+IdentityPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Exercise the production transport on loopback without relaxing the
		// separate inventory host/privileged-port validation in get().
		resp, err := client.http.Do(req)
		if err != nil {
			return reused, err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("callback status %d", resp.StatusCode)
		}
		return reused, err
	}
	for i := range 2 {
		reused, err := request()
		if err != nil || reused != (i == 1) {
			t.Fatalf("request %d: reused=%t, err=%v", i, reused, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatal("initial callback requests did not reach the inventory")
	}
	pins.replace(bytes.Repeat([]byte{0x22}, refvalues.DigestSize))
	if _, err := request(); !errors.Is(err, armtls.ErrPolicyViolation) {
		t.Fatalf("retired inventory connection carried a request: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatal("a retired node reached the inventory HTTP handler")
	}
	verified := len(verifier.VerifyRequests())
	pins.replace(nil)
	if _, err := request(); !errors.Is(err, armtls.ErrUnpinned) {
		t.Fatalf("empty node set allowed a callback: %v", err)
	}
	if calls.Load() != 2 || len(verifier.VerifyRequests()) != verified {
		t.Fatal("empty node pins reached the inventory or attestation verifier")
	}
	pins.replace(digest)
	if reused, err := request(); err != nil || reused {
		t.Fatalf("restored node set did not use a fresh authenticated connection: reused=%t, err=%v", reused, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(clientCertificates) != 3 || !bytes.Equal(clientCertificates[0], clientCertificates[2]) || attestations.Load() != 1 {
		t.Fatal("changing server trust replaced the callback client's own certificate")
	}
}

// A complete node-image replacement with the generation production HA exposes.
type inventoryPins struct {
	mu         sync.Mutex
	current    refvalues.ReferenceValues
	generation uint64
}

func (p *inventoryPins) replace(digest []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = refvalues.ReferenceValues{Family: teetypes.FamilySNP}
	if len(digest) != 0 {
		p.current.Images = []remote.ImagePin{{Name: "inventory", Digest: bytes.Clone(digest)}}
	}
	p.generation++
}

func (p *inventoryPins) Current() refvalues.ReferenceValues {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

func (p *inventoryPins) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

func (p *inventoryPins) Refresh() error { return nil }
