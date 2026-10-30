package podprovider

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func providerCDSPolicy(t *testing.T, launch []byte) []byte {
	t.Helper()
	policy, err := refvalues.Format(refvalues.ReferenceValues{Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "independent-cds", Digest: bytes.Repeat([]byte{0x88}, 48), LaunchFile: launch}}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestStaticAndGenericLaunchKeepIndependentCDSTrust(t *testing.T) {
	cfg := fixtureConfig(t)
	static, err := cfg.launch(fixturePod())
	if err != nil {
		t.Fatal(err)
	}
	generic, err := cfg.genericLaunch(identityKey(cfg.ProviderID, "generic-cds-check"))
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []createRequest{static, generic} {
		if req.Trust.InitData.Format != launchconfig.SchemaVersion {
			t.Fatal("launch envelope and document schema differ")
		}
		doc, err := signedDocument(req.Trust)
		if err != nil {
			t.Fatal(err)
		}
		if doc.CDS != cfg.cds || doc.CDS.Address != "cds.example.test:8443" {
			t.Fatal("signed launch lost explicit DNS-addressed CDS trust")
		}
		pins, err := refvalues.Parse([]byte(doc.CDS.Measurements))
		if err != nil {
			t.Fatal(err)
		}
		if doc.Image.Platform != "tdx" || pins.Family != teetypes.FamilySNP || len(pins.Images) != 1 || !bytes.Equal(pins.Images[0].Digest, bytes.Repeat([]byte{0x88}, 48)) || len(pins.Images[0].LaunchFile) == 0 || len(pins.Images[0].Anchor) != 0 {
			t.Fatal("CDS trust was derived from the Pod image or cluster server key")
		}
	}
}

func TestCDSRotationDrainsIdlePoolWithoutRewritingFrozenTrust(t *testing.T) {
	for _, kind := range []string{"address", "policy"} {
		t.Run(kind, func(t *testing.T) {
			r, cloud, _, pod := poolFixture(t)
			r.cfg.MaxPods = 1
			cloud.holdDeletion = true
			if err := r.maintainPools(t.Context()); err != nil {
				t.Fatal(err)
			}
			before := onlyPool(t, r)
			frozen := before.record.Request
			rec, _, err := r.ensureRecord(t.Context(), pod)
			if err != nil {
				t.Fatal(err)
			}
			if !r.compatiblePool(before.record) || r.checkPoolBinding(rec, before.record) != nil {
				t.Fatal("matching CDS trust was refused")
			}
			next := *r.cfg
			if kind == "address" {
				next.CDSAddress = "replacement-cds.example.test:9443"
			} else if err := os.WriteFile(next.CDSImagePolicyFile, providerCDSPolicy(t, []byte("schemaVersion: c8s-cds/v1\nclusterID: replacement\n")), 0600); err != nil {
				t.Fatal(err)
			}
			if err := next.loadTrust(); err != nil {
				t.Fatal(err)
			}
			r.cfg = &next
			if r.compatiblePool(before.record) {
				t.Fatal("idle allocation retained changed CDS trust")
			}
			if err := r.checkPoolBinding(rec, before.record); err != nil {
				t.Fatalf("rotation rewrote frozen Pod/allocation trust: %v", err)
			}
			fresh := *rec
			fresh.Request, err = next.launch(pod)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.checkPoolBinding(&fresh, before.record); err == nil {
				t.Fatal("new Pod authority was assigned to an old CDS allocation")
			}
			if err := r.maintainPools(t.Context()); err != nil {
				t.Fatal(err)
			}
			after := onlyPool(t, r)
			if !after.record.DeleteRequested || after.record.Deleted || cloud.deletes != 1 || !reflect.DeepEqual(after.record.Request, frozen) {
				t.Fatal("rotation changed frozen bytes or released capacity before confirmed deletion")
			}
		})
	}
}
