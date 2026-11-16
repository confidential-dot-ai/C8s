package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// An injected sidecar dials the endpoint its node mounts; without a mount
// --cds-url stands as it was given, and Validate canonicalises it.
func TestResolveCDSEndpointTakesTheNodesEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cds-address")
	if err := os.WriteFile(path, cmdsutil.FormatCDSAddress("cds.example.org:30808"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath := nodeAddressPath
	nodeAddressPath = path
	t.Cleanup(func() { nodeAddressPath = previousPath })
	var logged bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	injected := &Config{}
	if err := injected.ResolveCDSEndpoint(); err != nil {
		t.Fatalf("ResolveCDSEndpoint: %v", err)
	}
	if injected.CDSURL != "https://cds.example.org:30808" {
		t.Fatalf("CDSURL = %q, want the node's endpoint", injected.CDSURL)
	}
	line := logged.String()
	if !strings.Contains(line, `msg="CDS endpoint resolved"`) ||
		!strings.Contains(line, "cds_url=https://cds.example.org:30808") ||
		!strings.Contains(line, "from_node=true") {
		t.Fatalf("logged %q, want the resolved endpoint line", line)
	}

	nodeAddressPath = filepath.Join(t.TempDir(), "absent")
	supplied := &Config{CDSURL: "https://cds:8443/"}
	if err := supplied.ResolveCDSEndpoint(); err != nil {
		t.Fatalf("ResolveCDSEndpoint: %v", err)
	}
	if supplied.CDSURL != "https://cds:8443/" {
		t.Fatalf("CDSURL = %q, want --cds-url as it was given", supplied.CDSURL)
	}
}

func TestEndpointSelectsCompiledShape(t *testing.T) {
	if got, want := (Config{}).Endpoint(), workloadclaims.InventoryEndpoint(); got != want {
		t.Fatalf("node-CVM endpoint = %q, want the compiled unix socket %q", got, want)
	}
	const timeout = 5 * time.Second
	// The endpoint check precedes the dial, so with a cancelled context
	// context.Canceled means workloadclaims accepted this shape. The key must be
	// real: a nil one fails at marshalling, short of the check.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = workloadclaims.FetchSandboxToken(ctx, workloadclaims.InventoryEndpoint(), timeout, pub, []byte("nonce"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("node endpoint not accepted by the compiled-endpoint check: %v", err)
	}
	_, err = workloadclaims.FetchSandboxToken(ctx, "http://127.0.0.1:9999", timeout, pub, []byte("nonce"))
	if err == nil || errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "endpoint must be") {
		t.Fatalf("non-compiled endpoint not rejected ahead of the transport: %v", err)
	}
}
