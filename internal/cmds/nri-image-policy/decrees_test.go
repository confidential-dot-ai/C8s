package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
)

func decreeKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testImage(c string) cdsha.DecreeImage {
	return cdsha.DecreeImage{MRTD: strings.Repeat(c, 96), RTMR1: strings.Repeat(c, 96), RTMR2: strings.Repeat(c, 96)}
}

// The plugin follows a signed decree for its own CDS clients and rewrites the
// policy it mounts into credential clients in place, so running pods (whose
// bind mount pins the file's inode) see the new pins too.
func TestFollowedDecreesRewriteTheMountedPolicyInPlace(t *testing.T) {
	k, pub := decreeKey(t)
	dir := t.TempDir()
	cfg := pullConfig{URL: "https://cds:30808", AttestationApiURL: "http://127.0.0.1:1", CDSMeasurementsConfig: "../../testdata/node-identities.json"}
	if src, err := cfg.cdsDecrees("tdx", slog.Default()); src != nil || err != nil {
		t.Fatalf("off: %v %v", src, err)
	}
	cfg.CDSDecrees = &cdsDecreesInfo{ClusterID: "c1", DecreeKey: "junk"}
	if _, err := cfg.cdsDecrees("tdx", slog.Default()); err == nil {
		t.Fatal("a bad decree key accepted")
	}
	cfg.CDSDecrees.DecreeKey = pub
	src, err := cfg.cdsDecrees("tdx", slog.Default())
	if err != nil || src == nil {
		t.Fatalf("on: %v %v", src, err)
	}
	launch, _ := cfg.policySet("tdx")
	cfg.decrees = src
	if set, _ := cfg.pinsSet("tdx"); len(set.Images) != len(launch.Images) {
		t.Fatal("before any decree the set is the launch document's")
	}

	img := testImage("e")
	pin, _ := img.Pin()
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "i", BaseEpoch: 3, Kind: cdsha.UpdateMeasurements,
		Measurements: []string{pin}, Images: []cdsha.DecreeImage{img}, ExpiresAt: time.Now().Add(time.Hour)}, k)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := pem.Decode([]byte(pub))
	src.Source, err = cdspins.New(cdspins.Config{ClusterID: "c1", DecreeKey: der.Bytes, Bootstrap: launch, MinInterval: time.Nanosecond,
		Fetch: func(context.Context) (*cdsha.SignedDecree, error) { return &sd, nil }})
	if err != nil {
		t.Fatal(err)
	}
	mounted := filepath.Join(dir, "cds-pins.json")
	doc, _ := refvalues.Format(launch)
	if err := os.WriteFile(mounted, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	var before syscall.Stat_t
	_ = syscall.Stat(mounted, &before)
	src.mounted = mounted
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("decree not taken: %v %v", changed, err)
	}
	var after syscall.Stat_t
	_ = syscall.Stat(mounted, &after)
	if before.Ino != after.Ino {
		t.Fatal("the mounted policy was replaced, not rewritten: running pods keep the old inode")
	}
	got, err := refvalues.Load(mounted)
	if err != nil || len(got.Images) == 0 || !bytes.Equal(got.Images[0].Digest, bytes.Repeat([]byte{0xee}, 48)) {
		t.Fatalf("mounted policy does not pin the decreed image: %v", err)
	}
	if set, _ := cfg.pinsSet("tdx"); len(set.Images) == 0 || !bytes.Equal(set.Images[0].Digest, got.Images[0].Digest) {
		t.Fatal("the plugin's own set does not follow the decree")
	}

	cfg.CDSMeasurementsConfig = ""
	if _, err := cfg.cdsDecrees("tdx", slog.Default()); err == nil {
		t.Fatal("decrees without a CDS policy accepted")
	}
}

// At start the enforcer takes the replicas' decree before it hands out any
// pins, within a bound; a failed fetch is logged as an error and leaves the
// launch document's pins.
func TestTakeFirstDecree(t *testing.T) {
	k, pub := decreeKey(t)
	cfg := pullConfig{URL: "https://cds:30808", AttestationApiURL: "http://127.0.0.1:1", CDSMeasurementsConfig: "../../testdata/node-identities.json"}
	launch, err := cfg.policySet("tdx")
	if err != nil {
		t.Fatal(err)
	}
	img := testImage("e")
	pin, _ := img.Pin()
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "i", BaseEpoch: 3, Kind: cdsha.UpdateMeasurements,
		Measurements: []string{pin}, Images: []cdsha.DecreeImage{img}, ExpiresAt: time.Now().Add(time.Hour)}, k)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := pem.Decode([]byte(pub))
	follow := func(fetch cdspins.Fetcher) (*followedPins, *bytes.Buffer) {
		src, err := cdspins.New(cdspins.Config{ClusterID: "c1", DecreeKey: der.Bytes, Bootstrap: launch, Fetch: fetch})
		if err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		return &followedPins{Source: src, logger: slog.New(slog.NewTextHandler(&log, nil))}, &log
	}
	served, log := follow(func(context.Context) (*cdsha.SignedDecree, error) { return &sd, nil })
	takeFirstDecree(served, time.Second, served.logger)
	if e, ok := served.Epoch(); !ok || e != 3 || strings.Contains(log.String(), "ERROR") {
		t.Fatalf("decree not taken at start: epoch %d %v, log %s", e, ok, log.String())
	}
	start := time.Now()
	hung, log := follow(func(ctx context.Context) (*cdsha.SignedDecree, error) { <-ctx.Done(); return nil, ctx.Err() })
	takeFirstDecree(hung, 50*time.Millisecond, hung.logger)
	if _, ok := hung.Epoch(); ok || !strings.Contains(log.String(), "level=ERROR") || time.Since(start) > 5*time.Second {
		t.Fatalf("unanswered fetch: log %s after %v", log.String(), time.Since(start))
	}
}
