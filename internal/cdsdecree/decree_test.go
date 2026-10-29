package cdsdecree

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

const (
	clusterID  = "lane"
	launchFile = "schemaVersion: c8s-cds/v1\nclusterID: lane\n"
)

func operatorKey(t *testing.T) (*ecdsa.PrivateKey, []*ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, []*ecdsa.PublicKey{&key.PublicKey}
}

// cdsImages pins one CDS image to the launch file every replica boots, as
// `c8s cds config new` writes it.
func cdsImages(t *testing.T, digest byte) []byte {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:       "cds-smp4",
			Digest:     bytes.Repeat([]byte{digest}, refvalues.DigestSize),
			LaunchFile: []byte(launchFile),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func cdsPins(t *testing.T, digest byte) *PinDocument {
	t.Helper()
	pins, err := NewPinDocument(cdsImages(t, digest))
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

// nodeImages pins one node image, which binds no launch file of its own.
func nodeImages(t *testing.T) *NodeImages {
	t.Helper()
	measurements, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: []remote.ImagePin{{
			Name:   "node",
			Digest: bytes.Repeat([]byte{0x22}, refvalues.DigestSize),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	images, err := NewNodeImages(measurements)
	if err != nil {
		t.Fatal(err)
	}
	return images
}

// complete is a decree of one kind carrying everything that kind must.
func complete(t *testing.T, kind Kind) Decree {
	t.Helper()
	d := Decree{
		ClusterID: clusterID,
		IntentID:  NewIntentID(),
		Kind:      kind,
		ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Second),
	}
	for _, name := range kinds[kind].must {
		setField(t, &d, name)
	}
	return d
}

// setField gives one field a value the kinds carrying it accept.
func setField(t *testing.T, d *Decree, name string) {
	t.Helper()
	switch name {
	case "base_version":
		d.BaseVersion = 7
	case "cds_pins":
		d.CDSPins = cdsPins(t, 0x11)
	case "node_pins":
		d.NodePins = nodeImages(t)
	case "target_member":
		d.TargetMember = "ahn7yq4qnkwftxo6ihoyu2bxpi"
	case "target_address":
		d.TargetAddress = "10.0.0.5:8443"
	case "issued_at_ms":
		d.IssuedAtMS = time.Now().UnixMilli()
	case "genesis_ca":
		d.GenesisCA = strings.Repeat("ab", sha256.Size)
	case "resume_version":
		d.ResumeVersion = 9
	case "alone":
		d.Alone = true
	case "recover_intent":
		d.RecoverIntent = NewIntentID()
	default:
		t.Fatalf("no value for decree field %q", name)
	}
}

func everyKind() []Kind {
	return []Kind{
		Genesis,
		UpdateMeasurements,
		RotateKey,
		Recover,
		DismissRecover,
		Admit,
	}
}

// A decree reaches the cluster as an object on a board the host controls, so
// what the cluster checks is what it decodes from those bytes.
func TestASignedDecreeVerifiesAfterItsBoardObject(t *testing.T) {
	key, keys := operatorKey(t)
	for _, kind := range everyKind() {
		t.Run(string(kind), func(t *testing.T) {
			signed, err := Sign(complete(t, kind), key)
			if err != nil {
				t.Fatal(err)
			}
			object, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			read, err := Parse(object)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(read, keys, clusterID); err != nil {
				t.Fatalf("a signed %s decree was refused after a round trip: %v", kind, err)
			}
		})
	}
}

// Every field the operator signed is covered: a host editing one leaves a
// decree nothing adopts.
func TestVerifyRefusesAnEditedDecree(t *testing.T) {
	key, keys := operatorKey(t)
	for _, tc := range []struct {
		name string
		edit func(*Decree)
	}{
		{"another cluster", func(d *Decree) { d.ClusterID = "other" }},
		{"another intent", func(d *Decree) { d.IntentID = NewIntentID() }},
		{"another kind", func(d *Decree) { d.Kind = RotateKey }},
		{"a later base version", func(d *Decree) { d.BaseVersion++ }},
		{"other images", func(d *Decree) { d.CDSPins = cdsPins(t, 0x33) }},
		{"another launch file digest", func(d *Decree) { d.CDSPins.LaunchFileSHA256 = strings.Repeat("00", 32) }},
		{"a longer life", func(d *Decree) { d.ExpiresAt = d.ExpiresAt.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := Sign(complete(t, UpdateMeasurements), key)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(&signed.Decree)
			if err := Verify(signed, keys, clusterID); err == nil {
				t.Fatal("an edited decree verified")
			}
		})
	}
}

// Decrees are signed by a key of the cluster's operatorPublicKeys, any one of
// which the operator may use.
func TestVerifyTakesOneKeyOfTheCluster(t *testing.T) {
	_, first := operatorKey(t)
	second, pinned := operatorKey(t)
	signed, err := Sign(complete(t, RotateKey), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(signed, append(first, pinned...), clusterID); err != nil {
		t.Fatalf("a decree signed with the second pinned key was refused: %v", err)
	}
	if err := Verify(signed, first, clusterID); err == nil {
		t.Fatal("a decree signed with a key the cluster does not pin verified")
	}
	if err := Verify(signed, nil, clusterID); err == nil {
		t.Fatal("a decree verified against no key at all")
	}
}

// A kind carries exactly its own fields, so a decree can neither be short of
// what it needs nor smuggle in what another kind acts on.
func TestEachKindCarriesItsOwnFields(t *testing.T) {
	key, keys := operatorKey(t)
	for _, kind := range everyKind() {
		t.Run(string(kind), func(t *testing.T) {
			for _, name := range kinds[kind].must {
				short := complete(t, kind)
				clearField(t, &short, name)
				if err := verifySigned(t, key, keys, short); err == nil {
					t.Fatalf("a %s decree without %s verified", kind, name)
				}
			}
			for name := range fields {
				if kinds[kind].allows(name) {
					continue
				}
				extra := complete(t, kind)
				setField(t, &extra, name)
				if err := verifySigned(t, key, keys, extra); err == nil {
					t.Fatalf("a %s decree carrying %s verified", kind, name)
				}
			}
		})
	}
}

// Every field name a kind lists is a field, so a mistyped name cannot leave a
// field unchecked.
func TestEveryKindNamesFields(t *testing.T) {
	for _, kind := range everyKind() {
		shape, known := kinds[kind]
		if !known {
			t.Fatalf("%s has no shape", kind)
		}
		for _, name := range append(shape.must, shape.may...) {
			if _, field := fields[name]; !field {
				t.Fatalf("a %s decree is said to carry %q, which is not a decree field", kind, name)
			}
		}
	}
}

func TestVerifyRefusesAnUnknownKind(t *testing.T) {
	key, keys := operatorKey(t)
	d := complete(t, RotateKey)
	d.Kind = "SetVoters"
	if err := verifySigned(t, key, keys, d); err == nil {
		t.Fatal("a decree of an unknown kind verified")
	}
}

// An intent id names the decree's board object and the cluster's record of it.
func TestIntentIDNamesABoardObject(t *testing.T) {
	key, keys := operatorKey(t)
	for _, tc := range []struct {
		name string
		id   string
		ok   bool
	}{
		{"fresh", NewIntentID(), true},
		{"empty", "", false},
		{"uppercase", strings.ToUpper(NewIntentID()), false},
		{"a path", strings.Repeat("../other/", 3) + "x", false},
		{"a dotted name", strings.Repeat("a", intentIDSize-5) + ".json", false},
		{"shorter", NewIntentID()[1:], false},
		{"longer", NewIntentID() + "a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := complete(t, RotateKey)
			d.IntentID = tc.id
			switch err := verifySigned(t, key, keys, d); {
			case tc.ok && err != nil:
				t.Fatalf("intent id %q was refused: %v", tc.id, err)
			case !tc.ok && err == nil:
				t.Fatalf("intent id %q verified", tc.id)
			}
		})
	}
}

// A replica adopts a decree while it is unexpired, on its own clock, so an
// expiry before the operator's own signing time refuses every adoption.
func TestDecreeIsIssuedWithinItsExpiry(t *testing.T) {
	key, keys := operatorKey(t)
	d := complete(t, Genesis)
	d.IssuedAtMS = d.ExpiresAt.Add(time.Second).UnixMilli()
	if err := verifySigned(t, key, keys, d); err == nil {
		t.Fatal("a decree issued past its expiry verified")
	}
	d = complete(t, Genesis)
	d.ExpiresAt = time.Time{}
	if err := verifySigned(t, key, keys, d); err == nil {
		t.Fatal("a decree with no expiry verified")
	}
}

// verifySigned signs d and checks it as a replica does.
func verifySigned(t *testing.T, key *ecdsa.PrivateKey, keys []*ecdsa.PublicKey, d Decree) error {
	t.Helper()
	signed, err := Sign(d, key)
	if err != nil {
		t.Fatal(err)
	}
	return Verify(signed, keys, clusterID)
}

func clearField(t *testing.T, d *Decree, name string) {
	t.Helper()
	switch name {
	case "base_version":
		d.BaseVersion = 0
	case "cds_pins":
		d.CDSPins = nil
	case "node_pins":
		d.NodePins = nil
	case "target_member":
		d.TargetMember = ""
	case "target_address":
		d.TargetAddress = ""
	case "issued_at_ms":
		d.IssuedAtMS = 0
	case "genesis_ca":
		d.GenesisCA = ""
	case "resume_version":
		d.ResumeVersion = 0
	case "alone":
		d.Alone = false
	case "recover_intent":
		d.RecoverIntent = ""
	default:
		t.Fatalf("no way to clear decree field %q", name)
	}
}
