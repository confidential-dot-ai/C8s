//go:build linux

package armtlsmesh

import (
	"bytes"
	"crypto/x509/pkix"
	"io"
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func namedMeshLeaf(t *testing.T, name string, digest byte) leafSpec {
	t.Helper()
	if name == "" {
		return leafSpec{}
	}
	ext, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             name,
		AllowlistVersion: "1",
		AllowlistDigest:  bytes.Repeat([]byte{digest}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return leafSpec{armtlsExt: &ext}
}

func TestOutboundPeerWorkloadPolicy(t *testing.T) {
	for _, tc := range []struct {
		name           string
		local, peer    string
		peerDigest     byte
		malformed      bool
		malformedLocal bool
		allowed        bool
	}{
		{name: "matching workload and policy", local: "router", peer: "worker", peerDigest: 1, allowed: true},
		{name: "wrong workload", local: "router", peer: "other", peerDigest: 1},
		{name: "wrong policy", local: "router", peer: "worker", peerDigest: 2},
		{name: "missing local stamp", peer: "worker", peerDigest: 1},
		{name: "missing peer stamp", local: "router", peerDigest: 1},
		{name: "malformed peer stamp", local: "router", peer: "worker", peerDigest: 1, malformed: true},
		{name: "malformed local stamp", local: "router", peer: "worker", peerDigest: 1, malformedLocal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMeshCA(t, time.Hour)
			local := namedMeshLeaf(t, tc.local, 1)
			remote := namedMeshLeaf(t, tc.peer, tc.peerDigest)
			if tc.malformedLocal {
				local.armtlsExt = &pkix.Extension{Id: armtls.OIDMatchedWorkload, Value: []byte{5, 0}}
			}
			if tc.malformed {
				remote.armtlsExt = &pkix.Extension{Id: armtls.OIDMatchedWorkload, Value: []byte{5, 0}}
			}
			volume := testVolume(t)
			publishSet(t, volume, ca.issue(t, local))
			peerTLS, _ := ca.meshConfigsFor(t, remote)
			peer := startEchoServer(t, peerTLS)
			_, listeners := startTestEndpoint(t, volume, testPeerAddress, peer.addr(), "worker")
			app, err := net.Dial("tcp", listeners.outbound.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			app.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := app.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			n, err := io.ReadFull(app, buf)
			if tc.allowed {
				if err != nil || string(buf[:n]) != "ping" {
					t.Fatalf("approved peer: received %q, error %v", buf[:n], err)
				}
			} else if n != 0 || err == nil {
				t.Fatalf("refused peer received application data: %q, error %v", buf[:n], err)
			}
		})
	}
}
