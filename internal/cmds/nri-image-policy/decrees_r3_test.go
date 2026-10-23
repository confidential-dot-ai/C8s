package nriimagepolicy

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
)

func r3Followed(t *testing.T) *followedPins {
	t.Helper()
	k, pub := decreeKey(t)
	cfg := pullConfig{CDSMeasurementsConfig: "../../testdata/node-identities.json"}
	launch, err := cfg.policySet("tdx")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := pem.Decode([]byte(pub))
	var fetches atomic.Uint64
	src, err := cdspins.New(cdspins.Config{ClusterID: "c1", DecreeKey: der.Bytes, Bootstrap: launch, MinInterval: time.Nanosecond,
		Fetch: func(context.Context) (*cdsha.SignedDecree, error) {
			epoch := fetches.Add(1)
			if epoch > 2 {
				epoch = 2
			}
			image := testImage("e")
			if epoch == 2 {
				image = testImage("f")
			}
			pin, _ := image.Pin()
			sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: string(rune('a' + epoch)), BaseEpoch: epoch, Kind: cdsha.UpdateMeasurements, Measurements: []string{pin}, Images: []cdsha.DecreeImage{image}, ExpiresAt: time.Now().Add(time.Hour)}, k)
			return &sd, err
		}})
	if err != nil {
		t.Fatal(err)
	}
	return &followedPins{Source: src, logger: slog.Default(), mounted: filepath.Join(t.TempDir(), "pins.json")}
}

func TestR3MountedPinsPublicationOrdering(t *testing.T) {
	f := r3Followed(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	f.writeFile = func(name string, doc []byte, mode os.FileMode) error {
		if writes.Add(1) == 1 {
			close(entered)
			<-release
		}
		return os.WriteFile(name, doc, mode)
	}
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() { defer close(doneA); f.Refresh(t.Context()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer barrier")
	}
	go func() { defer close(doneB); f.Refresh(t.Context()) }()
	// An unfixed publisher completes B while A is paused. A serialized
	// publisher cannot, so release A after the bounded observation window.
	select {
	case <-doneB:
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for _, done := range []chan struct{}{doneA, doneB} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("refresh stuck")
		}
	}
	got, err := os.ReadFile(f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	want, err := refvalues.Format(f.Current())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("mounted policy rolled back behind current policy")
	}
}

func TestR3MountedPinsRetryFailedPublication(t *testing.T) {
	f := r3Followed(t)
	// Fail both decree publications; the third fetch returns unchanged epoch 2.
	var writes int
	f.writeFile = func(name string, doc []byte, mode os.FileMode) error {
		writes++
		if writes <= 2 {
			return errors.New("write failed")
		}
		return os.WriteFile(name, doc, mode)
	}
	for range 3 {
		f.Refresh(t.Context())
	}
	got, err := os.ReadFile(f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := refvalues.Format(f.Current())
	if !bytes.Equal(got, want) {
		t.Fatal("failed mounted publication not retried")
	}
}
