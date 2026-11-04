package cmdsutil

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// mountPins writes the policy an enforcer mounts for its credential clients.
func mountPins(t *testing.T, path, measurement string) {
	t.Helper()
	document := testutil.CDSPinDocument(measurement, testutil.CDSLaunchFile)
	if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A client re-reads the mounted policy on a pin miss, so its next request is
// made against the image CDS now runs.
func TestNodePinsFollowARewrittenPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	mountPins(t, path, testutil.TestMeasurement)
	pins, err := FollowNodePins(t.Context(), path)
	if err != nil {
		t.Fatalf("FollowNodePins: %v", err)
	}
	first := pins.Generation()

	mountPins(t, path, testutil.NextCDSImage)
	if err := pins.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pins.Generation() == first {
		t.Fatal("the client held its set after the enforcer rewrote the policy")
	}
	if got := hex.EncodeToString(pins.Current().Images[0].Digest); got != testutil.NextCDSImage {
		t.Fatalf("pins name %s, want the image the enforcer wrote", got)
	}
	if err := pins.Refresh(); err != nil || pins.Generation() == first {
		t.Fatalf("a re-read of unchanged bytes: %v at generation %d", err, pins.Generation())
	}
}

// The enforcer truncates and writes the same inode, so a client can read the
// file halfway through: that leaves the set it holds.
func TestNodePinsKeepTheirSetOnAHalfWrittenPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	mountPins(t, path, testutil.TestMeasurement)
	pins, err := FollowNodePins(t.Context(), path)
	if err != nil {
		t.Fatalf("FollowNodePins: %v", err)
	}

	half := testutil.CDSPinDocument(testutil.NextCDSImage, testutil.CDSLaunchFile)
	if err := os.WriteFile(path, []byte(half[:len(half)/2]), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pins.Refresh(); err == nil {
		t.Fatal("a half-written policy was taken as a pin set")
	}
	if got := hex.EncodeToString(pins.Current().Images[0].Digest); got != testutil.TestMeasurement {
		t.Fatalf("pins name %s, want the set the client held", got)
	}
}

// A client whose requests keep succeeding has no pin miss to re-read on, so
// the source re-reads on its own.
func TestNodePinsRereadWithoutAPinMiss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	mountPins(t, path, testutil.TestMeasurement)
	pins, err := FollowNodePins(t.Context(), path)
	if err != nil {
		t.Fatalf("FollowNodePins: %v", err)
	}
	first := pins.Generation()

	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	go pins.reread(ctx, time.Millisecond)
	mountPins(t, path, testutil.NextCDSImage)
	deadline := time.Now().Add(5 * time.Second)
	for pins.Generation() == first && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pins.Generation() == first {
		t.Fatal("the client held a retired set, with nothing making it read the policy again")
	}
}

// A node that mounts no policy leaves its clients on the pins their flags
// name, and a mount it cannot read fails them instead.
func TestFollowNodePinsReportsNoPolicyWhereTheNodeMountsNone(t *testing.T) {
	pins, err := FollowNodePins(t.Context(), filepath.Join(t.TempDir(), "absent.json"))
	if pins != nil || err != nil {
		t.Fatalf("pins = %v, err = %v, want neither", pins, err)
	}

	unbound := filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(unbound, []byte(`{"schema_version":"1","tee":"sev-snp","measurements":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := FollowNodePins(t.Context(), unbound); err == nil {
		t.Fatal("a policy that is not one CDS VM's identity was accepted")
	}
}
