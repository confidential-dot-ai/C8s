package podprovider

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
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

func TestCDSRotationDrainsIdlePoolWithoutRewritingFrozenTrust(t *testing.T) {
	for _, kind := range []string{"address", "policy", "floor"} {
		t.Run(kind, func(t *testing.T) {
			r, cloud, _, _ := poolFixture(t)
			r.cfg.MaxPods = 1
			cloud.holdDeletion = true
			var nextDecree string
			if kind == "floor" {
				key, _, policy := providerCDSDecreeFixture(t, r.cfg)
				r.cfg.CDSPinDecreeFile, _ = writeProviderPinDecree(t, key, r.cfg.ClusterID, policy, 7)
				nextDecree, _ = writeProviderPinDecree(t, key, r.cfg.ClusterID, policy, 8)
				if err := r.cfg.loadTrust(); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.maintainPools(t.Context()); err != nil {
				t.Fatal(err)
			}
			before := onlyPool(t, r)
			frozen := before.record.Request
			if !r.compatiblePool(before.record) {
				t.Fatal("matching CDS trust was refused")
			}
			next := *r.cfg
			if kind == "address" {
				next.CDSAddress = "replacement-cds.example.test:9443"
			} else if kind == "floor" {
				next.CDSPinDecreeFile = nextDecree
			} else if err := os.WriteFile(next.CDSImagePolicyFile, providerCDSPolicy(t, []byte("schemaVersion: c8s-cds/v1\nclusterID: replacement\n")), 0600); err != nil {
				t.Fatal(err)
			}
			if err := next.loadTrust(); err != nil {
				t.Fatal(err)
			}
			if kind == "floor" && (next.cds.Measurements != r.cfg.cds.Measurements || next.cds.PinFloor != r.cfg.cds.PinFloor+1) {
				t.Fatal("floor-only rotation changed the pin set or lost the signed version")
			}
			r.cfg = &next
			if r.compatiblePool(before.record) {
				t.Fatal("idle allocation retained changed CDS trust")
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
