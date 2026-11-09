//go:build !c8s_node

package worker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// The worker image's measurements: its launch digest, and on TDX its kernel
// and command-line registers.
var (
	workerDigest   = bytes.Repeat([]byte{0x77}, refvalues.DigestSize)
	workerRTMRs    = map[int][]byte{1: bytes.Repeat([]byte{0x71}, refvalues.DigestSize), 2: bytes.Repeat([]byte{0x72}, refvalues.DigestSize)}
	workerFamilies = []teetypes.Family{teetypes.FamilySNP, teetypes.FamilyTDX}
)

// admitFixture is a worker document and what Admit checks it against: the CDS
// pin it carries, the worker image, and a cluster certifying one anchored
// server image.
type admitFixture struct {
	family   teetypes.Family
	doc      Document
	document []byte
	in       AdmitInputs
}

func newAdmitFixture(t *testing.T, family teetypes.Family) admitFixture {
	t.Helper()
	doc := testDocument(t)
	worker := remote.ImagePin{Name: "worker", Digest: workerDigest}
	if family == teetypes.FamilyTDX {
		worker.Registers = workerRTMRs
	}
	server := remote.ImagePin{Name: "server", Digest: bytes.Repeat([]byte{0x55}, refvalues.DigestSize), Anchor: []byte(publicKeyPEM(t))}
	return admitFixture{
		family:   family,
		doc:      doc,
		document: marshalDocument(t, doc),
		in: AdmitInputs{
			CDSPin:      []byte(doc.CDS.Measurements),
			WorkerImage: formatPins(t, family, worker),
			Nodes:       formatPins(t, family, server),
		},
	}
}

func formatPins(t *testing.T, family teetypes.Family, images ...remote.ImagePin) []byte {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{Family: family, Images: images})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func admitted(t *testing.T, f admitFixture, document []byte) Admission {
	t.Helper()
	a, err := Admit(bytes.NewReader(document), f.in)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// independentDigest is the launch file digest of document on family, computed
// without the code under test.
func independentDigest(family teetypes.Family, document []byte) []byte {
	if family == teetypes.FamilyTDX {
		digest := sha512.Sum384(document)
		return digest[:]
	}
	digest := sha256.Sum256(document)
	return digest[:]
}

func TestAdmitAddsTheWorkerImageBoundToTheDocumentsBytes(t *testing.T) {
	for _, family := range workerFamilies {
		t.Run(string(family), func(t *testing.T) {
			f := newAdmitFixture(t, family)
			current, _ := refvalues.Parse(f.in.Nodes)
			got, err := refvalues.Parse(admitted(t, f, f.document).Nodes)
			if err != nil {
				t.Fatal(err)
			}
			missing, extra := refvalues.Diff(current, got)
			if got.Family != family || len(missing) != 0 || len(extra) != 1 {
				t.Fatalf("admitted set drops %d entries and adds %d, want the set in force and one worker entry", len(missing), len(extra))
			}
			want := independentDigest(family, f.document)
			if !bytes.Equal(extra[0].LaunchFileDigest, want) || !bytes.Equal(extra[0].Digest, workerDigest) {
				t.Fatalf("worker entry = %+v, want the worker image bound to digest %x", extra[0], want)
			}
			if extra[0].Name != "worker-"+hex.EncodeToString(want[:6]) {
				t.Fatalf("worker entry is named %q", extra[0].Name)
			}
		})
	}
}

// A cluster of workers has no set in force before its first worker, which
// starts the set alone.
func TestAdmitStartsAFirstSetWithTheWorkerImageAlone(t *testing.T) {
	for _, family := range workerFamilies {
		t.Run(string(family), func(t *testing.T) {
			f := newAdmitFixture(t, family)
			a, err := AdmitFirst(bytes.NewReader(f.document), f.in.CDSPin, f.in.WorkerImage)
			if err != nil {
				t.Fatal(err)
			}
			set, err := refvalues.Parse(a.Nodes)
			if err != nil {
				t.Fatal(err)
			}
			want := independentDigest(family, f.document)
			if set.Family != family || len(set.Images) != 1 || !bytes.Equal(set.Images[0].LaunchFileDigest, want) {
				t.Fatalf("first set = %+v, want the worker image alone, bound to digest %x", set, want)
			}
			resp, platform := evidence(family, f.document, workerRTMRs)
			if err := enforce(t, a, resp, platform); err != nil {
				t.Fatalf("the worker launched with the admitted document was refused: %v", err)
			}
		})
	}
}

func TestAdmitPrintsTheFactsTheDocumentCarries(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilySNP)
	var report strings.Builder
	if err := admitted(t, f, f.document).Report(&report); err != nil {
		t.Fatal(err)
	}
	stdout := report.String()
	block, _ := pem.Decode([]byte(f.doc.Kubernetes.CACertificate))
	fingerprint := sha256.Sum256(block.Bytes)
	for _, fact := range []string{
		"API server        acme.k8s.example:443\n",
		"CA subject        \"CN=kubernetes\"\n",
		"CA SHA-256        " + hex.EncodeToString(fingerprint[:]) + "\n",
		"pod range         10.52.0.0/16\n",
		"Service range     10.53.0.0/16\n",
		"cluster DNS       10.53.0.10\n",
		"CDS address       cds.acme.example:8443\n",
		"CDS pin floor     1\n",
		"router TLS SAN    c8s.acme.example\n",
		"router hostnames  api.acme.example\n",
		"Signing certifies these node images:\n  server\n",
		"  worker-" + hex.EncodeToString(independentDigest(f.family, f.document)[:6]) + "  bound to this document, launch_file_digest " + hex.EncodeToString(independentDigest(f.family, f.document)) + "\n",
	} {
		if !strings.Contains(stdout, fact) {
			t.Errorf("stdout lacks %q:\n%s", fact, stdout)
		}
	}
}

// differentOnSecondRead serves first to its end, then second to a reader that
// reads it again.
type differentOnSecondRead struct {
	current, second *bytes.Reader
}

func (r *differentOnSecondRead) Read(p []byte) (int, error) {
	n, err := r.current.Read(p)
	if errors.Is(err, io.EOF) {
		r.current = r.second
	}
	return n, err
}

func TestAdmitReadsTheDocumentOnce(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilyTDX)
	other := f.doc
	other.Kubernetes.APIServer = "evil.example:443"
	document := &differentOnSecondRead{current: bytes.NewReader(f.document), second: bytes.NewReader(marshalDocument(t, other))}
	got, err := Admit(document, f.in)
	if err != nil {
		t.Fatal(err)
	}
	want := admitted(t, f, f.document)
	if !bytes.Equal(got.Nodes, want.Nodes) || got.document.Kubernetes.APIServer != f.doc.Kubernetes.APIServer {
		t.Fatal("a second read of the document changed what Admit returned")
	}
	if !bytes.Equal(got.digest, independentDigest(f.family, f.document)) {
		t.Fatalf("Admit bound digest %x, want the first read's", got.digest)
	}
}

func TestAdmitRefusesWhatTheCustomerCannotAdmit(t *testing.T) {
	unbound := remote.ImagePin{Name: "unbound", Digest: bytes.Repeat([]byte{0x66}, refvalues.DigestSize)}
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *admitFixture)
		want   string
	}{
		{"a cluster DNS address in the pod range, outside the Service range", func(t *testing.T, f *admitFixture) {
			doc := f.doc
			doc.Kubernetes.ClusterDNS = "10.52.0.10"
			f.document = marshalDocument(t, doc)
		}, "must be inside kubernetes.serviceCIDR"},
		{"a CDS pin of another family", func(t *testing.T, f *admitFixture) {
			pins, _ := refvalues.Parse(f.in.CDSPin)
			pins.Family = teetypes.FamilyTDX
			f.in.CDSPin = formatPins(t, pins.Family, pins.Images...)
		}, "cds.measurements pins a sev-snp CDS and --cds-pin a tdx one"},
		{"another CDS pin", func(t *testing.T, f *admitFixture) {
			f.in.CDSPin = []byte(testCDSPin(t, cdsConfig(t, "192.168.0.0/16")))
		}, "pins another CDS than --cds-pin"},
		{"a worker image bound already", func(t *testing.T, f *admitFixture) {
			pin := remote.ImagePin{Name: "worker", Digest: workerDigest, Anchor: []byte(publicKeyPEM(t))}
			f.in.WorkerImage = formatPins(t, f.family, pin)
		}, "binds a launch already"},
		{"a set in force with an unbound entry", func(t *testing.T, f *admitFixture) {
			f.in.Nodes = formatPins(t, f.family, unbound)
		}, `entry "unbound" binds no launch`},
		{"a set in force of another family", func(t *testing.T, f *admitFixture) {
			pin := unbound
			pin.Anchor = []byte(publicKeyPEM(t))
			f.in.Nodes = formatPins(t, teetypes.FamilyTDX, pin)
		}, "--worker-image pins a sev-snp image and --nodes tdx ones"},
		{"a set in force admitting this document", func(t *testing.T, f *admitFixture) {
			f.in.Nodes = admitted(t, *f, f.document).Nodes
		}, "--nodes already holds an entry named"},
		{"a set in force admitting this document under another name", func(t *testing.T, f *admitFixture) {
			held, _ := refvalues.Parse(admitted(t, *f, f.document).Nodes)
			held.Images[len(held.Images)-1].Name = "renamed"
			f.in.Nodes = formatPins(t, held.Family, held.Images...)
		}, "--nodes already admits the worker image with this document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdmitFixture(t, teetypes.FamilySNP)
			tc.change(t, &f)
			if _, err := Admit(bytes.NewReader(f.document), f.in); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// Diff matches on the launch binding too, so a pin of the same CDS image bound
// to another configuration is another CDS.
func TestAdmitRefusesACDSPinBoundToAnotherConfiguration(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilySNP)
	pins, _ := refvalues.Parse(f.in.CDSPin)
	otherConfiguration := []byte(cdsConfig(t, "192.168.0.0/16"))
	for i := range pins.Images {
		pins.Images[i].LaunchFile = otherConfiguration
	}
	f.in.CDSPin = formatPins(t, pins.Family, pins.Images...)
	if _, err := Admit(bytes.NewReader(f.document), f.in); err == nil || !strings.Contains(err.Error(), "pins another CDS") {
		t.Fatalf("got %v, want the pin bound to another configuration refused", err)
	}
}

func TestAdmitComparesCDSPinsByWhatTheyPin(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilySNP)
	var compact bytes.Buffer
	if err := json.Compact(&compact, f.in.CDSPin); err != nil {
		t.Fatal(err)
	}
	f.in.CDSPin = compact.Bytes()
	if _, err := Admit(bytes.NewReader(f.document), f.in); err != nil {
		t.Fatalf("a pin written another way was refused: %v", err)
	}
}

// A second document for the same image, such as one naming a new API server
// CA, is admitted beside the first.
func TestAdmitKeepsTheEntriesInForce(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilyTDX)
	first := admitted(t, f, f.document)
	rotated := f.doc
	rotated.Kubernetes.CACertificate = selfSigned(t, caTemplate())
	f.in.Nodes = first.Nodes
	second := admitted(t, f, marshalDocument(t, rotated))

	before, _ := refvalues.Parse(first.Nodes)
	after, _ := refvalues.Parse(second.Nodes)
	missing, extra := refvalues.Diff(before, after)
	const server, workerUnderEachDocument = 1, 2
	if len(missing) != 0 || len(extra) != 1 || len(after.Images) != server+workerUnderEachDocument {
		t.Fatalf("admitting a second document dropped %d entries and added %d to %d, want none dropped and one added", len(missing), len(extra), len(after.Images))
	}
}

func TestAdmitWritesTheSchemaThatReadsLaunchFileDigests(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilySNP)
	schema := func(document []byte) string {
		var declared struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(document, &declared); err != nil {
			t.Fatal(err)
		}
		return declared.SchemaVersion
	}
	if got := schema(f.in.Nodes); got != "1" {
		t.Fatalf("the set in force declares schema %q, want a schema 1 set", got)
	}
	if got := schema(admitted(t, f, f.document).Nodes); got != "2" {
		t.Fatalf("the admitted set declares schema %q, want 2", got)
	}
}

// The cluster reads the set Admit returned, byte for byte, from the signed
// decree carrying it.
func TestADecreeCarriesTheAdmittedSetByteForByte(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilyTDX)
	a := admitted(t, f, f.document)
	images, err := cdsdecree.NewNodeImages(a.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(cdsdecree.Decree{
		ClusterID:   "acme",
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.SetNodeImages,
		ExpiresAt:   time.Now().Add(time.Minute).UTC().Truncate(time.Second),
		BaseVersion: 3,
		NodePins:    images,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	object, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	read, err := cdsdecree.Parse(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := cdsdecree.Verify(read, []*ecdsa.PublicKey{&key.PublicKey}, "acme"); err != nil {
		t.Fatal(err)
	}
	carried, err := json.Marshal(read.Decree.NodePins)
	if err != nil {
		t.Fatal(err)
	}
	var written bytes.Buffer
	if err := json.Compact(&written, a.Nodes); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(carried, written.Bytes()) {
		t.Fatalf("the decree carries\n%s\nnot what Admit returned\n%s", carried, written.Bytes())
	}
}

// evidence is a verified report of the worker image with these registers,
// launched with document, its NRI plugin having extended RTMR[3] on TDX.
func evidence(family teetypes.Family, document []byte, rtmrs map[int][]byte, extended ...string) (remote.VerifyResponse, teetypes.PlatformType) {
	claims := teetypes.Claims{LaunchDigest: hex.EncodeToString(workerDigest)}
	platform := teetypes.PlatformSNP
	if family == teetypes.FamilyTDX {
		platform = teetypes.PlatformTDX
		launched := sha512.Sum384(document)
		rtmr3 := runtimemeasure.FromDigestsSeeded(runtimemeasure.Extend(runtimemeasure.Zero, launched), extended)
		claims.PlatformData = map[string]any{
			"rtmr_1": hex.EncodeToString(rtmrs[1]),
			"rtmr_2": hex.EncodeToString(rtmrs[2]),
			"rtmr_3": hex.EncodeToString(rtmr3[:]),
		}
	} else {
		hostData := sha256.Sum256(document)
		claims.InitData = hostData[:]
	}
	return remote.VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true, Platform: platform, Claims: claims}}, platform
}

func enforce(t *testing.T, a Admission, resp remote.VerifyResponse, platform teetypes.PlatformType, claimed ...string) error {
	t.Helper()
	pins, err := refvalues.Parse(a.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	return armtls.EnforceImages(resp, pins.Images, platform, claimed)
}

func TestAdmittedEntriesAdmitTheWorkerImageWithThatDocumentOnly(t *testing.T) {
	for _, family := range workerFamilies {
		t.Run(string(family), func(t *testing.T) {
			f := newAdmitFixture(t, family)
			a := admitted(t, f, f.document)
			resp, platform := evidence(family, f.document, workerRTMRs)
			if err := enforce(t, a, resp, platform); err != nil {
				t.Fatalf("the worker launched with the admitted document was refused: %v", err)
			}
			for name, change := range map[string]func(*Document){
				"CA":          func(d *Document) { d.Kubernetes.CACertificate = selfSigned(t, caTemplate()) },
				"CDS address": func(d *Document) { d.CDS.Address = "cds2.acme.example:8443" },
				"pod range":   func(d *Document) { d.Kubernetes.PodCIDR = "10.54.0.0/16" },
			} {
				doc := f.doc
				change(&doc)
				other := marshalDocument(t, doc)
				if _, err := Parse(other); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				resp, platform := evidence(family, other, workerRTMRs)
				if err := enforce(t, a, resp, platform); err == nil {
					t.Errorf("a worker launched with the document's %s changed was admitted", name)
				}
			}
		})
	}
}

func TestAdmittedEntriesHoldTheWorkerImagesRegisters(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilyTDX)
	a := admitted(t, f, f.document)
	for _, register := range []int{1, 2} {
		rtmrs := map[int][]byte{1: workerRTMRs[1], 2: workerRTMRs[2]}
		rtmrs[register] = bytes.Repeat([]byte{0x99}, refvalues.DigestSize)
		resp, platform := evidence(f.family, f.document, rtmrs)
		if err := enforce(t, a, resp, platform); err == nil {
			t.Errorf("a worker of another RTMR[%d] launched with the admitted document was admitted", register)
		}
	}
}

func TestAdmittedEntriesAcceptTheWorkersRuntimeLog(t *testing.T) {
	f := newAdmitFixture(t, teetypes.FamilyTDX)
	a := admitted(t, f, f.document)
	policy := "sha256:" + strings.Repeat("ab", 32)
	resp, platform := evidence(f.family, f.document, workerRTMRs, policy)
	if err := enforce(t, a, resp, platform, policy); err != nil {
		t.Fatalf("a worker whose NRI plugin extended a policy was refused: %v", err)
	}
	if err := enforce(t, a, resp, platform); err == nil {
		t.Fatal("a worker hiding its runtime log was admitted")
	}
}
