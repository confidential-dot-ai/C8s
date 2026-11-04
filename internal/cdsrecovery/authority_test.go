package cdsrecovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

type authorityFixture struct {
	identity  Identity
	key       []byte
	signer    ed25519.PrivateKey
	record    []byte
	origin    string
	verifier  *mockapi.Stub
	verdict   mockapi.Verdict
	recipient atomic.Pointer[Recipient]
	stall     atomic.Bool
}

func newAuthorityFixture(t *testing.T, cluster string) *authorityFixture {
	t.Helper()
	launch := []byte("recovery test launch " + cluster)
	hash := sha256.Sum256(launch)
	f := &authorityFixture{identity: Identity{ClusterID: cluster, ConfigSHA256: hex.EncodeToString(hash[:]), Prefix: cluster}, key: make([]byte, 32), verifier: mockapi.New(t)}
	if _, err := rand.Read(f.key); err != nil {
		t.Fatal(err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.signer = signer
	f.verdict = mockapi.PassingVerdict(testutil.TestMeasurement)
	binding := runtimemeasure.HostData(launch)
	f.verdict.Claims.InitData = binding[:]
	f.verifier.SetVerdict(f.verdict)
	r, err := NewRecipient(f.identity)
	if err != nil {
		t.Fatal(err)
	}
	f.recipient.Store(r)
	server := testutil.NewARMTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.stall.Load() {
			<-r.Context().Done()
			return
		}
		if r.URL.Path != RequestPath {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(f.recipient.Load().Request())
	}))
	f.origin = server.URL
	f.record, err = Enroll(t.Context(), Enrollment{Identity: f.identity,
		Pins: []byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(launch))), Origins: []string{server.URL}},
		server.URL, f.verifier.URL(), f.key, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *authorityFixture) restore(t *testing.T) *Authority {
	t.Helper()
	a, err := NewAuthority(t.Context(), f.identity, f.record, f.key, f.signer, f.verifier.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func (f *authorityFixture) readGrant(t *testing.T, a *Authority) Material {
	t.Helper()
	g, err := a.Release(t.Context(), f.origin)
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.recipient.Load().Open(*g, f.signer.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Key, f.key) {
		t.Fatal("release changed cluster key")
	}
	t.Cleanup(func() { clear(m.Key) })
	return m
}

func TestAuthorityRestartCannotRegrantGenesisToReplacement(t *testing.T) {
	f := newAuthorityFixture(t, "one")
	a := f.restore(t)
	if !f.readGrant(t, a).AllowGenesis {
		t.Fatal("initial recipient was not authorized")
	}
	a.Close()
	// Retrying the initial process after authority loss stays idempotent.
	a = f.restore(t)
	if !f.readGrant(t, a).AllowGenesis {
		t.Fatal("authority restart changed initialization binding")
	}
	a.Close()
	replacement, err := NewRecipient(f.identity)
	if err != nil {
		t.Fatal(err)
	}
	f.recipient.Store(replacement)
	a = f.restore(t)
	if f.readGrant(t, a).AllowGenesis {
		t.Fatal("replacement received genesis permission")
	}
	if _, err := a.Release(t.Context(), "https://unapproved.invalid"); err == nil {
		t.Fatal("dialed unapproved origin")
	}
	badVerdict := f.verdict
	badVerdict.Claims.LaunchDigest = strings.Repeat("ab", 48)
	f.verifier.SetVerdict(badVerdict)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("released key to unapproved measured code")
	}
	badVerdict = f.verdict
	changedLaunch := runtimemeasure.HostData([]byte("operator-replaced launch configuration"))
	badVerdict.Claims.InitData = changedLaunch[:]
	f.verifier.SetVerdict(badVerdict)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("released key under an unapproved launch configuration")
	}
	f.verifier.SetVerdict(f.verdict)
	wrong, _ := NewRecipient(Identity{ClusterID: "other", ConfigSHA256: f.identity.ConfigSHA256, Prefix: f.identity.Prefix})
	f.recipient.Store(wrong)
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("released key across clusters")
	}
	for _, secret := range [][]byte{f.key, f.signer} {
		if bytes.Contains(f.record, secret) || bytes.Contains(f.record, []byte(base64.StdEncoding.EncodeToString(secret))) {
			t.Fatal("registration exported custody material")
		}
	}
}

func TestAuthorityRefusesMissingOrRewrittenRegistration(t *testing.T) {
	f := newAuthorityFixture(t, "one")
	var original registration
	if err := json.Unmarshal(f.record, &original); err != nil {
		t.Fatal(err)
	}
	// Even another legitimately signed record must match the custodian's
	// independently selected cluster/configuration, not choose its own scope.
	original.Policy.Identity.ClusterID = "other"
	original.Signature = ed25519.Sign(f.signer, registrationBytes(original))
	other, _ := json.Marshal(original)
	if a, err := NewAuthority(t.Context(), f.identity, other, f.key, f.signer, f.verifier.URL()); err == nil {
		a.Close()
		t.Fatal("restored another signed custody identity")
	}
	for name, change := range map[string]func(*registration){
		"identity": func(r *registration) { r.Policy.Identity.ClusterID = "other" },
		"genesis":  func(r *registration) { r.Genesis[0] ^= 1 },
		"origin":   func(r *registration) { r.Policy.Origins = []string{"https://evil.invalid"} },
		"pins":     func(r *registration) { r.Policy.Pins = []byte("{}") },
		"version":  func(r *registration) { r.Version++ },
	} {
		t.Run(name, func(t *testing.T) {
			var r registration
			if err := json.Unmarshal(f.record, &r); err != nil {
				t.Fatal(err)
			}
			change(&r)
			body, _ := json.Marshal(r)
			if a, err := NewAuthority(t.Context(), f.identity, body, f.key, f.signer, f.verifier.URL()); err == nil {
				a.Close()
				t.Fatal("accepted rewritten enrollment")
			}
		})
	}
	for _, record := range [][]byte{nil, []byte("{}"), append(bytes.Clone(f.record), []byte(" {}")...)} {
		if a, err := NewAuthority(t.Context(), f.identity, record, f.key, f.signer, f.verifier.URL()); err == nil {
			a.Close()
			t.Fatal("recovered without intact enrollment")
		}
	}
	if a, err := NewAuthority(t.Context(), f.identity, f.record, bytes.Repeat([]byte{99}, 32), f.signer, f.verifier.URL()); err == nil {
		a.Close()
		t.Fatal("accepted replacement custody key")
	}
}

func TestAuthorityBackpressureIsPerClusterAndCloseDrains(t *testing.T) {
	f, other := newAuthorityFixture(t, "one"), newAuthorityFixture(t, "two")
	a, b := f.restore(t), other.restore(t)
	f.stall.Store(true)
	answers := make(chan error, 16)
	for range 16 {
		go func() { _, err := a.Release(context.Background(), f.origin); answers <- err }()
	}
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for a.Stats().Admitted != 16 || a.Stats().Active != 4 {
		select {
		case <-deadline:
			t.Fatal("requests did not fill bounded actor queue")
		case <-tick.C:
		}
	}
	if _, err := a.Release(t.Context(), f.origin); !errors.Is(err, requestgate.ErrBusy) {
		t.Fatalf("overflow: %v", err)
	}
	other.readGrant(t, b)
	a.Close()
	for range 16 {
		select {
		case err := <-answers:
			if err == nil {
				t.Fatal("shutdown released a stalled grant")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown failed to drain")
		}
	}
	if stats := a.Stats(); stats.Admitted != 0 || stats.Active != 0 {
		t.Fatalf("permits leaked: %+v", stats)
	}
	if _, err := a.Release(t.Context(), f.origin); err == nil {
		t.Fatal("closed authority issued a grant")
	}
}
