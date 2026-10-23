package cdsha

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Pause verification with the old pins while the epoch sweep completes.
func TestR3RevokedPeerTracksAfterRecheck(t *testing.T) {
	a, b, _, m := muxPeers(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	m.verifier.pins = func() []string {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return []string{"m1"}
		}
		return []string{"m2"}
	}
	c, err := tls.Dial("tcp", m.ln.Addr().String(), b.tls)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("verification barrier")
	}
	m.recheck() // epoch update's only sweep, while route is not yet tracked
	close(release)
	id := string(a.id)
	if _, err = c.Write(append([]byte{muxRaft, byte(len(id))}, id...)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() { pc, _ := m.Accept(); accepted <- pc }()
	select {
	case pc := <-accepted:
		if pc != nil {
			pc.Close()
			t.Fatal("revoked m1 connection admitted after final epoch recheck")
		}
	case <-time.After(2 * time.Second):
		// Fixed implementations close rather than deliver; close mux releases Accept.
		m.Close()
	}
}

// A sweep must not snapshot policy before taking the admission lock: an
// older sweep could otherwise miss an insertion after a newer policy change.
func TestR3SweepSnapshotsPinsUnderAdmissionLock(t *testing.T) {
	_, _, _, m := muxPeers(t, nil)
	entered, done := make(chan struct{}), make(chan struct{})
	m.verifier.pins = func() []string { close(entered); return []string{"m1"} }
	m.connMu.Lock()
	go func() { m.recheck(); close(done) }()
	early := false
	select {
	case <-entered:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	m.connMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sweep stuck")
	}
	if early {
		t.Fatal("sweep read policy outside admission critical section")
	}
}

func TestR3AdmissionSnapshotsPinsUnderLock(t *testing.T) {
	_, _, _, m := muxPeers(t, nil)
	raw, other := net.Pipe()
	defer raw.Close()
	defer other.Close()
	c := tls.Client(raw, m.tls)
	entered, done := make(chan struct{}), make(chan struct{})
	m.verifier.pins = func() []string { close(entered); return []string{"m1"} }
	m.connMu.Lock()
	var pc *peerConn
	var err error
	go func() { pc, err = m.track(c, Claims{Measurement: "m1"}); close(done) }()
	early := false
	select {
	case <-entered:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	m.connMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("admission stuck")
	}
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if early {
		t.Fatal("admission read policy outside critical section")
	}
}

func TestR3TrackRejectsRevokedAndClosed(t *testing.T) {
	_, _, _, m := muxPeers(t, nil)
	raw, other := net.Pipe()
	defer raw.Close()
	defer other.Close()
	c := tls.Client(raw, m.tls)
	m.verifier.pins = func() []string { return []string{"m2"} }
	if pc, err := m.track(c, Claims{Measurement: "m1"}); err == nil {
		pc.Close()
		t.Fatal("revoked peer tracked")
	}
	m.Close()
	if pc, err := m.track(c, Claims{Measurement: "m2"}); err == nil {
		pc.Close()
		t.Fatal("closed mux admitted peer")
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if len(m.conns) != 0 {
		t.Fatal("refused peer registered")
	}
}
