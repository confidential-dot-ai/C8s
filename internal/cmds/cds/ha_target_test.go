package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// A replica named by DNS carries the name as SNI, so a passthrough front door
// shared by several replicas can route to it; one named by address carries
// none, as before.
func TestAReplicaNamedByDNSIsReachedWithItsNameAsSNI(t *testing.T) {
	c := newReplicatedCluster(t)
	var mu sync.Mutex
	var served []string
	handler := http.NewServeMux()
	handler.HandleFunc("GET "+statusPath, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served = append(served, r.TLS.ServerName)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(cdsha.Status{ID: "member"})
	})
	server := testutil.NewARMTLSServer(t, handler)
	at, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		entry string
		sni   string
	}{
		{entry: "localhost:" + at.Port(), sni: "localhost"},
		{entry: at.Host, sni: ""},
	} {
		mu.Lock()
		served = nil
		mu.Unlock()
		r := replica{
			address:  tc.entry,
			cdsPin:   c.cdsPinPath,
			verifier: c.verifier(),
		}
		reported, err := r.status(context.Background())
		if err != nil {
			t.Fatalf("status of %s: %v", tc.entry, err)
		}
		if reported.ID != "member" {
			t.Fatalf("status of %s = %+v", tc.entry, reported)
		}
		mu.Lock()
		got := slices.Clone(served)
		mu.Unlock()
		if len(got) == 0 || slices.ContainsFunc(got, func(name string) bool { return name != tc.sni }) {
			t.Fatalf("requests to %s carried SNI %q, want every one %q", tc.entry, got, tc.sni)
		}
	}
}

func TestAReplicaBaseKeepsAnEntrysNameAndPort(t *testing.T) {
	address := netip.MustParseAddrPort("10.0.0.7:8443")
	for entry, want := range map[string]string{
		"r0.lane.cds.example.org":      "https://r0.lane.cds.example.org:8443",
		"r0.lane.cds.example.org:9443": "https://r0.lane.cds.example.org:9443",
		"10.0.0.7":                     "https://10.0.0.7:8443",
	} {
		got, err := replicaBase(entry, address)
		if err != nil || got != want {
			t.Errorf("replicaBase(%q) = %q, %v, want %q", entry, got, err, want)
		}
	}
}

// Names a front door routes by SNI resolve to its one address and stay one
// replica each; a name standing for several replicas is reached at each of
// their addresses.
func TestReplicasSharingAFrontDoorStayDistinct(t *testing.T) {
	door := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.5:8443")}
	pool := []netip.AddrPort{
		netip.MustParseAddrPort("10.0.0.7:8443"),
		netip.MustParseAddrPort("10.0.0.8:8443"),
	}
	for _, tc := range []struct {
		entry     string
		answering []netip.AddrPort
		want      []string
	}{
		{entry: "r0.lane.cds.example.org", answering: door, want: []string{"r0.lane.cds.example.org"}},
		{entry: "r1.lane.cds.example.org", answering: door, want: []string{"r1.lane.cds.example.org"}},
		{entry: "replicas.lane.svc", answering: pool, want: []string{"10.0.0.7:8443", "10.0.0.8:8443"}},
		{entry: "10.0.0.7", answering: pool[:1], want: []string{"10.0.0.7:8443"}},
	} {
		if got := reachedAs(tc.entry, tc.answering); !slices.Equal(got, tc.want) {
			t.Errorf("reachedAs(%q) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

// A replica answering past the limit is refused where it is read, so no
// truncated report or decree answer is parsed.
func TestAReplicaAnswerOverTheLimitIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxReplicaReport+1))
	}))
	t.Cleanup(server.Close)

	if _, err := replicaAnswer(context.Background(), server.Client(), server.URL, statusPath, maxReplicaReport); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("GET %s: %v", statusPath, err)
	}
	if _, err := postedDecree(context.Background(), server.Client(), server.URL, []byte("{}")); !errors.Is(err, readutil.ErrTooLarge) {
		t.Fatalf("POST %s: %v", decreesPath, err)
	}
}

// The signed routes are answered by any one replica, so an oversized answer
// costs that replica its turn instead of the command.
func TestAnOversizedAnswerMovesToTheNextReplica(t *testing.T) {
	c := newReplicatedCluster(t)
	replicas := c.replicasServing(t,
		map[string]any{pinDecreePath: map[string]string{"pad": strings.Repeat("x", maxReplicaReport)}},
		map[string]any{pinDecreePath: c.pinDecree(t, smp2Digest)},
	)

	address, body, err := signedStateOfAnyReplica(context.Background(), replicas, pinDecreePath, maxReplicaReport)
	if err != nil {
		t.Fatalf("signedStateOfAnyReplica: %v", err)
	}
	if address != replicas[1].address {
		t.Fatalf("answered by %s, want the second replica %s", address, replicas[1].address)
	}
	if _, err := cdsdecree.Parse(body); err != nil {
		t.Fatalf("parse the answer: %v", err)
	}
}
