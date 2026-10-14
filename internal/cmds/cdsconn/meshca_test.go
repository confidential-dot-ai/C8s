package cdsconn

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// The parts of the gate that decide without CDS. The CA comparison itself is
// exercised end to end by the secrets and volume command tests.
func TestMeshCAGateWithoutCDS(t *testing.T) {
	ctx := context.Background()

	g := MeshCAGate{What: "volume key"}
	if err := g.Precheck("https://cds.example"); err == nil || !strings.Contains(err.Error(), "refusing to write a volume key") {
		t.Fatalf("missing --mesh-ca: got %v", err)
	}
	if err := g.Check(ctx, &bytes.Buffer{}, nil, "https://cds.example"); err == nil {
		t.Fatal("Check accepted a missing --mesh-ca")
	}

	// --insecure plaintext is exempt, and silently: HTTPClient already warned.
	var stderr bytes.Buffer
	if err := g.Check(ctx, &stderr, nil, "http://cds.example"); err != nil || stderr.Len() != 0 {
		t.Fatalf("plaintext: err=%v stderr=%q", err, stderr.String())
	}

	g.Force = true
	if err := g.Precheck("https://cds.example"); err != nil {
		t.Fatalf("--force precheck: %v", err)
	}
	if err := g.Check(ctx, &stderr, nil, "https://cds.example"); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if !strings.Contains(stderr.String(), "writing this volume key without checking") {
		t.Fatalf("--force did not warn: %q", stderr.String())
	}

	g = MeshCAGate{What: "secret", Bundle: filepath.Join(t.TempDir(), "absent.pem")}
	if err := g.Precheck("https://cds.example"); err == nil || !strings.Contains(err.Error(), "read --mesh-ca") {
		t.Fatalf("absent bundle: got %v", err)
	}
}
