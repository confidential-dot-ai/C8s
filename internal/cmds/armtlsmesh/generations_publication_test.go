//go:build linux

package armtlsmesh

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A generation whose pointer names an incomplete publication is not read as a
// set: the leaf, the key and the CA come from one generation or from none.
func TestReadRefusesAnIncompletePublication(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	for _, missing := range []string{"chain", "key", "CA"} {
		t.Run(missing, func(t *testing.T) {
			volume := testVolume(t)
			publishSet(t, volume, ca.issue(t, leafSpec{}))
			target, err := os.Readlink(volume.pointerPath())
			if err != nil {
				t.Fatal(err)
			}
			names := map[string]string{
				"chain": volume.chainName,
				"key":   volume.keyName,
				"CA":    volume.caName,
			}
			if err := os.Remove(filepath.Join(volume.dir, target, names[missing])); err != nil {
				t.Fatal(err)
			}
			if _, err := volume.read(); err == nil {
				t.Fatalf("a publication without its %s was read as a generation", missing)
			}
		})
	}
}

// A pointer that is not a pointer leaves the adopted generation alone: the
// endpoint keeps serving what it validated rather than dropping the pod's mesh
// on an unreadable publication.
func TestAdoptPublicationKeepsTheGenerationOnAnUnreadablePointer(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	creds := &credentials{
		volume: volume,
		logger: discardLogger(),
	}
	creds.reload(time.Now())
	adopted, err := creds.usable(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(volume.pointerPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(volume.pointerPath(), []byte("generations/2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds.reload(time.Now())
	kept, err := creds.usable(time.Now())
	if err != nil {
		t.Fatalf("usable after an unreadable pointer: %v", err)
	}
	if kept != adopted {
		t.Error("an unreadable pointer replaced the adopted generation")
	}
}

// Credentials with no parsed leaf are refused: the handshake reads the leaf's
// window, so a provider without one could serve past expiry.
func TestPublishedCredentialsRequireAParsedLeaf(t *testing.T) {
	if _, err := newPublishedCredentials(nil); err == nil {
		t.Error("a nil certificate was accepted as published credentials")
	}
	ca := newMeshCA(t, time.Hour)
	g, err := adoptPublishedSet(ca.issue(t, leafSpec{}), time.Now(), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	unparsed := *g.cert
	unparsed.Leaf = nil
	if _, err := newPublishedCredentials(&unparsed); err == nil {
		t.Error("a certificate without a parsed leaf was accepted")
	}
}

// The watcher stops with its context, so a cancelled endpoint adopts nothing
// more.
func TestWatchGenerationsReturnsOnACancelledContext(t *testing.T) {
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	creds := &credentials{
		volume: volume,
		logger: discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	returned := make(chan struct{})
	go func() {
		creds.watchGenerations(ctx)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("watchGenerations did not return on a cancelled context")
	}
	if _, err := creds.usable(time.Now()); err == nil {
		t.Error("the cancelled watcher adopted a generation")
	}
}
