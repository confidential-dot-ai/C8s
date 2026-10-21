package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// TestTokenRouteIssuesAVerifiableToken is the contract get-cert and mock-cds
// share with this mock: the socket hands out a token naming the fixed sandbox,
// bound to the requester key and the challenge, and it verifies under the key
// IdentityPath serves.
func TestTokenRouteIssuesAVerifiableToken(t *testing.T) {
	const host = "10.42.0.7"
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		t.Fatal(err)
	}
	// gid 0: the test runs unprivileged, so there is no chgrp to the
	// production socket group.
	socket := filepath.Join(t.TempDir(), workloadclaims.SocketName)
	listener, err := workloadclaims.ListenUnix(socket, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = workloadclaims.ServeTokens(ctx, listener, fixedSandbox{id: sandboxID}, signer) }()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	token, err := workloadclaims.FetchSandboxToken(ctx, "unix://"+socket, 5*time.Second, &key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// The verification key comes from the served DER, the bytes mock-cds reads.
	served, err := x509.ParsePKIXPublicKey(signer.PublicKeyDER())
	if err != nil {
		t.Fatal(err)
	}
	inventoryPub, ok := served.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("served identity is %T, want an ECDSA key", served)
	}
	sandbox, err := token.Verify(inventoryPub, &key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if sandbox.SandboxID != sandboxID {
		t.Errorf("sandbox ID = %q, want %q", sandbox.SandboxID, sandboxID)
	}
	if sandbox.InventoryHost != host {
		t.Errorf("inventory host = %q, want %q", sandbox.InventoryHost, host)
	}
	// get-cert compares the ID against the leaf extension CDS stamps it into.
	if err := armtls.ValidateSandboxID(sandbox.SandboxID); err != nil {
		t.Error(err)
	}
}

// TestContainerIPIsAUsableInventoryHost covers the precondition
// NewSandboxTokenSigner enforces on the host this mock signs into its tokens.
func TestContainerIPIsAUsableInventoryHost(t *testing.T) {
	host, err := containerIP()
	if err != nil {
		t.Fatal(err)
	}
	if err := workloadclaims.ValidateInventoryHost(host); err != nil {
		t.Error(err)
	}
}
