package armtls

import (
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"sync"
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
