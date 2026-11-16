package armtls

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// The one image named says which peer the verifier admits. A handshake reads
// it, so it answers under a lock of its own.
type movingPins struct {
	mu         sync.Mutex
	current    string
	next       string
	generation uint64
	refreshes  int
}

func (m *movingPins) Current() refvalues.ReferenceValues {
	m.mu.Lock()
	defer m.mu.Unlock()
	return refvalues.ReferenceValues{
		Images: []remote.ImagePin{{
			Name:   m.current,
			Digest: imageDigest(m.current),
		}},
	}
}

func (m *movingPins) Generation() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation
}

func (m *movingPins) Refresh() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshes++
	if m.next == "" {
		return nil
	}
	m.current = m.next
	m.next = ""
	m.generation++
	return nil
}

func (m *movingPins) looks() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refreshes
}

func imageDigest(name string) []byte {
	digest := sha512.Sum384([]byte(name))
	return digest[:]
}

func TestFollowServerPinsChecksAgainstANewerSet(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)
	api := mockapi.New(t)
	api.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(imageDigest("new"))))
	pins := &movingPins{current: "old"}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	FollowServerPins(tlsCfg, pins, api.URL())
	presented := [][]byte{cert.Raw}

	if err := tlsCfg.VerifyPeerCertificate(presented, nil); err == nil {
		t.Fatal("a peer outside the pins was admitted")
	}
	if pins.looks() != 1 {
		t.Fatalf("the client looked for newer pins %d times, want the one look per refused handshake", pins.looks())
	}

	// The operator moved the pins: the same handshake passes against them.
	pins.next = "new"
	if err := tlsCfg.VerifyPeerCertificate(presented, nil); err != nil {
		t.Fatalf("a peer on the new pins was refused: %v", err)
	}
	if pins.looks() != 2 {
		t.Fatalf("the client looked for newer pins %d times, want one look per refused handshake", pins.looks())
	}

	// Later handshakes are checked against the set in force alone.
	if err := tlsCfg.VerifyPeerCertificate(presented, nil); err != nil || pins.looks() != 2 {
		t.Fatalf("a later handshake: %v, after %d looks", err, pins.looks())
	}
}

func TestFollowServerPinsRefusesWhereItCannotLook(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	FollowServerPins(tlsCfg, blindPins{}, mockapi.New(t).URL())

	if err := tlsCfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err == nil {
		t.Fatal("a peer outside the pins was admitted")
	}
}

// blindPins is a source whose cluster it cannot reach.
type blindPins struct{}

func (blindPins) Current() refvalues.ReferenceValues {
	return refvalues.ReferenceValues{
		Images: []remote.ImagePin{{
			Name:   "old",
			Digest: imageDigest("old"),
		}},
	}
}

func (blindPins) Generation() uint64 {
	return 1
}

func (blindPins) Refresh() error {
	return errUnreachableCluster
}

var errUnreachableCluster = errors.New("armtls_test: the cluster holding the pins is out of reach")

func TestFixedPinsNeverMove(t *testing.T) {
	images := refvalues.ReferenceValues{
		Images: []remote.ImagePin{{
			Name:   "node",
			Digest: imageDigest("node"),
		}},
	}
	fixed := FixedPins(images)

	if err := fixed.Refresh(); err != nil {
		t.Fatalf("a fixed set failed to refresh: %v", err)
	}
	if fixed.Generation() != 0 || len(fixed.Current().Images) != 1 {
		t.Fatalf("a fixed set reports generation %d and %d images", fixed.Generation(), len(fixed.Current().Images))
	}
}

// A server pinning its clients through a PinSource re-checks a refused
// handshake once against a newer set, as a client pinning its server does.
func TestFollowClientPinsChecksAgainstANewerSet(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)
	api := mockapi.New(t)
	api.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(imageDigest("new"))))
	pins := &movingPins{
		current: "old",
		next:    "new",
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	FollowClientPins(tlsCfg, pins, api.URL())

	if err := tlsCfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("a caller on the new pins was refused: %v", err)
	}
}

// unreachableCDS counts the attempts made through a CDS that answers nothing.
func unreachableCDS(attempts *atomic.Int64) func(Pins) (*http.Transport, error) {
	return func(Pins) (*http.Transport, error) {
		return &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			attempts.Add(1)
			return nil, errCDSUnreachable
		}}, nil
	}
}

var errCDSUnreachable = errors.New("armtls_test: the CDS in the pins answered nothing")

// A request that fails is made once more only where the set moved under it: a
// CDS relaunched on a newly decreed image answers the second attempt, and a
// peer the set in force refuses stays refused.
func TestARefreshingTransportRunsAgainOnlyWhereThePinsMoved(t *testing.T) {
	for name, next := range map[string]string{"the pins moved": "new", "the pins did not move": ""} {
		t.Run(name, func(t *testing.T) {
			var attempts atomic.Int64
			pins := &movingPins{
				current: "old",
				next:    next,
			}
			transport, err := NewRefreshingTransport(pins, unreachableCDS(&attempts))
			if err != nil {
				t.Fatalf("NewRefreshingTransport: %v", err)
			}
			request, err := http.NewRequest(http.MethodGet, "https://cds.example/allowlist", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := transport.RoundTrip(request); err == nil {
				t.Fatal("a request no CDS answered was reported as answered")
			}
			want := int64(1)
			if next != "" {
				want = 2
			}
			if attempts.Load() != want {
				t.Fatalf("the client made %d attempts, want %d", attempts.Load(), want)
			}
			if pins.looks() != 1 {
				t.Fatalf("the client looked for newer pins %d times, want one look per failed request", pins.looks())
			}
		})
	}
}

// A request whose body the caller cannot reproduce is made once: the second
// attempt would carry nothing.
func TestARefreshingTransportDoesNotReplayAnUnrepeatableBody(t *testing.T) {
	var attempts atomic.Int64
	pins := &movingPins{
		current: "old",
		next:    "new",
	}
	transport, err := NewRefreshingTransport(pins, unreachableCDS(&attempts))
	if err != nil {
		t.Fatalf("NewRefreshingTransport: %v", err)
	}
	request, err := http.NewRequest(http.MethodPut, "https://cds.example/allowlist", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.GetBody = nil

	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("a request no CDS answered was reported as answered")
	}
	if attempts.Load() != 1 {
		t.Fatalf("the client made %d attempts with a body it cannot send again, want one", attempts.Load())
	}
}

// Connections made under a retired set are closed with it: one of them
// carrying a later request would reach the image the operator removed.
func TestARefreshingTransportDropsTheConnectionsOfARetiredSet(t *testing.T) {
	pins := &movingPins{current: "old"}
	var built []*http.Transport
	transport, err := NewRefreshingTransport(pins, func(Pins) (*http.Transport, error) {
		next := &http.Transport{}
		built = append(built, next)
		return next, nil
	})
	if err != nil {
		t.Fatalf("NewRefreshingTransport: %v", err)
	}
	refreshing, ok := transport.(*refreshingTransport)
	if !ok {
		t.Fatalf("transport = %T, want the refreshing one", transport)
	}

	pins.next = "new"
	if err := pins.Refresh(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := refreshing.transport(); err != nil {
		t.Fatalf("the transport of the new set: %v", err)
	}
	if len(built) != 2 || built[0] == built[1] {
		t.Fatalf("the client built %d transports, want one per set it held", len(built))
	}
}
