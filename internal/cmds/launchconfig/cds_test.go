package launchconfig

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// cdsLaunchFile stands in for the configuration a CDS VM boots with; a pin
// binds its exact bytes.
const cdsLaunchFile = "schemaVersion: c8s-cds/v1\nclusterID: cluster-one\n"

// testCDSPin is the document `c8s cds config new` writes: one entry per launch
// digest the CDS VM may boot with, each bound to that file.
func testCDSPin(t *testing.T, family teetypes.Family, digests int) string {
	t.Helper()
	pins := refvalues.ReferenceValues{Family: family}
	for i := range digests {
		image := remote.ImagePin{
			Name:       fmt.Sprintf("cds-smp%d", 4*(i+1)),
			Digest:     mustDecodeHex(strings.Repeat(fmt.Sprintf("%02x", 0x50+i), 48)),
			LaunchFile: []byte(cdsLaunchFile),
		}
		if family == teetypes.FamilyTDX {
			image.Registers = map[int][]byte{
				1: mustDecodeHex(strings.Repeat("22", 48)),
				2: mustDecodeHex(strings.Repeat("33", 48)),
			}
		}
		pins.Images = append(pins.Images, image)
	}
	data, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// namesExternalCDS makes the fixture the v2 document of a cluster whose CDS
// runs on a confidential VM of its own.
func namesExternalCDS(t *testing.T, d *Document) {
	t.Helper()
	d.SchemaVersion = SchemaVersionV2
	d.CDS = &CDS{Address: "192.0.2.50:8443", Measurements: testCDSPin(t, teetypes.FamilySNP, 2)}
}

// testDigestOnlyPin pins the CDS image without binding the configuration it
// boots with, which is all a schema 1 document can express.
func testDigestOnlyPin(t *testing.T) string {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "cds", Digest: mustDecodeHex(strings.Repeat("50", 48))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A v2 document names the CDS, so the staged document carries the operator's
// pin document whole - every launch digest of the CDS image, on that VM's own
// TEE family - and names the address its clients dial. The node's own peer
// policy still comes from the image and launch keys it was signed with.
func TestStageNamesTheExternalCDS(t *testing.T) {
	doc, key, pub := testDocument(t, "tdx", Server)
	namesExternalCDS(t, &doc)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	staged, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := staged.CDSAddrPort().String(); got != "192.0.2.50:8443" {
		t.Fatalf("staged CDS endpoint = %s", got)
	}
	cds := stagedCDSPolicy(t, staged)
	if cds.Family != teetypes.FamilySNP || len(cds.Images) != 2 {
		t.Fatalf("CDS policy = %+v, want both SNP launch digests", cds)
	}
	for _, image := range cds.Images {
		if string(image.LaunchFile) != cdsLaunchFile || image.Anchor != nil {
			t.Fatalf("CDS pin %s is not bound to the launch file alone: %+v", image.Name, image)
		}
	}
	peers, err := refvalues.Load(cfg.path(Dir + "/peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if peers.Family != teetypes.FamilyTDX || len(peers.Images) != 2 {
		t.Fatalf("peer policy = %+v, want this node's launch identities", peers)
	}
}

// A v1 document derives both: the CDS runs beside the Kubernetes server, on
// the node image, under the server launch key.
func TestDerivedCDSIsTheServersOwnIdentity(t *testing.T) {
	doc, _, _ := testDocument(t, "tdx", Server)
	parsed, err := Parse(mustMarshalYAML(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.CDSAddrPort().String(); got != doc.Server.Address+":30808" {
		t.Fatalf("derived CDS endpoint = %s", got)
	}
	cds := stagedCDSPolicy(t, parsed)
	if len(cds.Images) != 1 || string(cds.Images[0].Anchor) != doc.Server.OperatorPublicKey {
		t.Fatalf("derived CDS policy = %+v, want the server launch identity alone", cds)
	}
	// A server that leaves its address to autodetection has no endpoint
	// until Stage resolves one.
	doc.Server.Address = ""
	parsed, err = Parse(mustMarshalYAML(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CDSAddrPort().IsValid() {
		t.Fatal("an unresolved server address yielded a CDS endpoint")
	}
}

// stagedCDSPolicy reads the policy document back as the node services write
// it for the clients that verify CDS.
func stagedCDSPolicy(t *testing.T, d *Document) refvalues.ReferenceValues {
	t.Helper()
	data, err := d.CDSPolicy()
	if err != nil {
		t.Fatal(err)
	}
	pins, err := refvalues.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

func mustMarshalYAML(t *testing.T, doc Document) []byte {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
