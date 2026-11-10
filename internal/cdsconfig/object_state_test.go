package cdsconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func testObjectStateWire(t *testing.T) *objectStateWire {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &objectStateWire{
		Bucket:              "cds-object-state-test",
		Key:                 "clusters/acme/current",
		Region:              "us-east-2",
		ExpectedBucketOwner: "123456789012",
		RecoveryAuthority:   base64.StdEncoding.EncodeToString(public),
	}
}

func TestObjectStateRidesTheMeasuredConfiguration(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	document := testDocument(
		t,
		operator,
		node,
	)
	document.ObjectState = testObjectStateWire(t)
	data := render(
		t,
		document,
	)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	state := cfg.ObjectState
	if state == nil || state.MaxBytes != 16<<20 || state.Workers != 4 || state.QueueCapacity != 64 {
		t.Fatalf(
			"wrong bounded defaults: %+v",
			state,
		)
	}
	if cfg.HA != nil || cfg.Nodes.Empty() {
		t.Fatal("object-backed replicas lost their fixed launch policy")
	}
	cluster, err := ReadCluster(data)
	if err != nil || cluster.Replicated {
		t.Fatal("object-backed replicas selected the peer-cluster decree protocol")
	}
	rendered := testDocumentFor(
		t,
		operator,
		node,
	)
	rendered.ObjectState = state
	data, err = Format(rendered)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(
		state,
		roundTrip.ObjectState,
	) {
		t.Fatal("Format changed the storage identity, recovery signer or admission bounds")
	}
}

func TestObjectStateStorageAndCustodyAreBoundByTheLaunchPin(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	doc := testDocumentFor(
		t,
		operator,
		node,
	)
	state, err := testObjectStateWire(t).parse()
	if err != nil {
		t.Fatal(err)
	}
	input := Inputs{
		ClusterID:     doc.ClusterID,
		OperatorKeys:  doc.OperatorKeys,
		ComponentSeed: []byte(testWorkloads),
		Nodes:         doc.Nodes,
		NodeCIDRs:     doc.NodeCIDRs,
		ClusterCIDRs: []string{
			"10.42.0.0/16",
			"10.43.0.0/16",
		},
		ObjectState:  state,
		ManifestPath: tdxManifest(t),
		Family:       teetypes.FamilyTDX,
	}
	configuration, pin, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(configuration)
	if err != nil || !reflect.DeepEqual(
		state,
		parsed.ObjectState,
	) {
		t.Fatal("Build lost the storage or recovery authority")
	}
	bound := parsePin(
		t,
		pin,
	)
	if len(bound.Images) != 1 || !bytes.Equal(
		bound.Images[0].LaunchFile,
		configuration,
	) {
		t.Fatal("the CDS pin did not bind storage and custody settings")
	}
}

func TestObjectStateRefusesUnsafeLaunchSettings(t *testing.T) {
	changes := map[string]func(*objectStateWire){
		"bucket missing":     func(w *objectStateWire) { w.Bucket = "" },
		"bucket ARN":         func(w *objectStateWire) { w.Bucket = "arn:aws:s3:::example" },
		"bucket address":     func(w *objectStateWire) { w.Bucket = "127.0.0.1" },
		"bucket empty label": func(w *objectStateWire) { w.Bucket = "cds..state" },
		"access point alias": func(w *objectStateWire) { w.Bucket = "other-s3alias" },
		"directory bucket":   func(w *objectStateWire) { w.Bucket = "other--x-s3" },
		"key missing":        func(w *objectStateWire) { w.Key = "" },
		"key root":           func(w *objectStateWire) { w.Key = "/current" },
		"key directory":      func(w *objectStateWire) { w.Key = "current/" },
		"key traversal":      func(w *objectStateWire) { w.Key = "cluster/../current" },
		"key dot":            func(w *objectStateWire) { w.Key = "cluster/./current" },
		"key repeated slash": func(w *objectStateWire) { w.Key = "cluster//current" },
		"key backslash":      func(w *objectStateWire) { w.Key = `cluster\current` },
		"key control":        func(w *objectStateWire) { w.Key = "cluster\x00current" },
		"key malformed UTF8": func(w *objectStateWire) { w.Key = "cluster\xffcurrent" },
		"key oversized": func(w *objectStateWire) {
			w.Key = strings.Repeat(
				"a",
				1025,
			)
		},
		"region implicit":         func(w *objectStateWire) { w.Region = "" },
		"region as origin":        func(w *objectStateWire) { w.Region = "https://s3.example" },
		"endpoint plaintext":      func(w *objectStateWire) { w.Endpoint = "http://s3.example" },
		"endpoint no host":        func(w *objectStateWire) { w.Endpoint = "https://" },
		"endpoint credentials":    func(w *objectStateWire) { w.Endpoint = "https://user:pass@s3.example" },
		"endpoint path":           func(w *objectStateWire) { w.Endpoint = "https://s3.example/bucket" },
		"endpoint query":          func(w *objectStateWire) { w.Endpoint = "https://s3.example?versionId=old" },
		"endpoint empty query":    func(w *objectStateWire) { w.Endpoint = "https://s3.example?" },
		"endpoint fragment":       func(w *objectStateWire) { w.Endpoint = "https://s3.example#old" },
		"endpoint empty fragment": func(w *objectStateWire) { w.Endpoint = "https://s3.example#" },
		"owner missing":           func(w *objectStateWire) { w.ExpectedBucketOwner = "" },
		"owner malformed":         func(w *objectStateWire) { w.ExpectedBucketOwner = "project-name" },
		"authority missing":       func(w *objectStateWire) { w.RecoveryAuthority = "" },
		"authority short":         func(w *objectStateWire) { w.RecoveryAuthority = "YWJj" },
		"authority noncanonical":  func(w *objectStateWire) { w.RecoveryAuthority += "\n" },
		"state negative":          func(w *objectStateWire) { w.MaxBytes = -1 },
		"state too small":         func(w *objectStateWire) { w.MaxBytes = 1<<20 - 1 },
		"state too large":         func(w *objectStateWire) { w.MaxBytes = 64<<20 + 1 },
		"workers negative":        func(w *objectStateWire) { w.Workers = -1 },
		"workers too many":        func(w *objectStateWire) { w.Workers = 17 },
		"queue negative":          func(w *objectStateWire) { w.QueueCapacity = -1 },
		"queue too large":         func(w *objectStateWire) { w.QueueCapacity = 257 },
	}
	for name, change := range changes {
		t.Run(
			name,
			func(t *testing.T) {
				wire := testObjectStateWire(t)
				change(wire)
				if _, err := wire.parse(); err == nil {
					t.Fatal("accepted unsafe object-state launch settings")
				}
			},
		)
	}
}

func TestObjectStateCannotCombineCoordinationModesOrLoseNodePins(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	document := testDocument(
		t,
		operator,
		node,
	)
	document.ObjectState = testObjectStateWire(t)
	ha := testHAWire()
	document.HA = &ha
	data := render(
		t,
		document,
	)
	if _, err := Parse(data); err == nil {
		t.Fatal("accepted both peer and storage coordination")
	}
	if _, err := ReadCluster(data); err == nil {
		t.Fatal("client selected a coordination mode for an ambiguous launch file")
	}
	document.HA = nil
	document.Nodes = ""
	if _, err := Parse(render(
		t,
		document,
	)); err == nil {
		t.Fatal("object-state CDS could start without fixed node pins")
	}
}

func TestObjectStateRejectsUndeclaredCredentials(t *testing.T) {
	_, operator := testKey(t)
	_, node := testKey(t)
	document := testDocument(
		t,
		operator,
		node,
	)
	document.ObjectState = testObjectStateWire(t)
	data := bytes.Replace(
		render(
			t,
			document,
		),
		[]byte("objectState:\n"),
		[]byte("objectState:\n    stateEncryptionKey: forbidden-plaintext\n"),
		1,
	)
	if _, err := Parse(data); err == nil || !strings.Contains(
		err.Error(),
		"stateEncryptionKey",
	) {
		t.Fatal("an undeclared encryption-key field was not rejected")
	}
}

func TestObjectStateDigestNamesEveryStorageAuthorityField(t *testing.T) {
	state, err := testObjectStateWire(t).parse()
	if err != nil {
		t.Fatal(err)
	}
	want := state.StorageDigest()
	changes := map[string]func(*ObjectState){
		"bucket":   func(s *ObjectState) { s.Bucket = "other-bucket" },
		"key":      func(s *ObjectState) { s.Key = "other/current" },
		"region":   func(s *ObjectState) { s.Region = "us-east-1" },
		"endpoint": func(s *ObjectState) { s.Endpoint = "https://storage.example" },
		"owner":    func(s *ObjectState) { s.ExpectedBucketOwner = "111111111111" },
	}
	for name, change := range changes {
		t.Run(
			name,
			func(t *testing.T) {
				other := *state
				change(&other)
				if other.StorageDigest() == want {
					t.Fatal("storage binding survived a change of authority")
				}
			},
		)
	}
	state.RecoveryAuthority = bytes.Repeat(
		[]byte{0x22},
		ed25519.PublicKeySize,
	)
	state.Workers++
	state.QueueCapacity++
	state.MaxBytes++
	if state.StorageDigest() != want {
		t.Fatal("changing recovery policy or admission limits renamed the stored ciphertext")
	}
}
