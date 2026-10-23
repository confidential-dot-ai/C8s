package nriimagepolicy

import (
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
	src.mirrorTo(mounted)
	if changed, err := src.Refresh(t.Context()); !changed || err != nil {
		t.Fatalf("decree not taken: %v %v", changed, err)
	}
	var after syscall.Stat_t
	_ = syscall.Stat(mounted, &after)
	if before.Ino != after.Ino {
		t.Fatal("the mounted policy was replaced, not rewritten: running pods keep the old inode")
	}
	got, err := refvalues.Load(mounted)
	if err != nil || len(got.Images) == 0 || got.Images[0].Registers[1] == nil {
		t.Fatalf("mounted policy: %v", err)
	}
	if set, _ := cfg.pinsSet("tdx"); len(set.Images) != len(got.Images) {
		t.Fatal("the plugin's own set does not follow the decree")
	}

	cfg.CDSMeasurementsConfig = ""
	if _, err := cfg.cdsDecrees("tdx", slog.Default()); err == nil {
		t.Fatal("decrees without a CDS policy accepted")
	}
	if err := rewriteInPlace(filepath.Join(dir, "absent"), nil); err == nil {
		t.Fatal("rewriting an absent file succeeded")
	}
}
