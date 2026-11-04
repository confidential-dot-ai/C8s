package cdsrecovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
)

func TestReleaseRefusesUnattestedOrUnboundRecipient(t *testing.T) {
	_, signer, _ := ed25519.GenerateKey(rand.Reader)
	launch := []byte("measured launch file")
	h := sha256.Sum256(launch)
	id := Identity{ClusterID: "one", ConfigSHA256: hex.EncodeToString(h[:]), Prefix: "one"}
	var called atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
	defer server.Close()
	target := Target{Origin: server.URL, AttestationURL: "http://127.0.0.1:1", Images: []remote.ImagePin{{Digest: make([]byte, 48), LaunchFile: launch}}}
	for name, change := range map[string]func(*Target){
		"ordinary TLS":    func(*Target) {},
		"unbound":         func(t *Target) { t.Images = []remote.ImagePin{{Digest: make([]byte, 48)}} },
		"wrong launch":    func(t *Target) { t.Images = []remote.ImagePin{{Digest: make([]byte, 48), LaunchFile: []byte("other")}} },
		"no pins":         func(t *Target) { t.Images = nil },
		"remote verifier": func(t *Target) { t.AttestationURL = "https://operator.example" },
		"HTTP":            func(t *Target) { t.Origin = "http://127.0.0.1:1" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := target
			change(&bad)
			if _, err := Release(context.Background(), id, bad, Material{Key: make([]byte, 32)}, signer); err == nil {
				t.Fatal("released without verified identity")
			}
		})
	}
	if called.Load() {
		t.Fatal("sent recovery request to unattested server")
	}
}
