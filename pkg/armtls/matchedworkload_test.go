package armtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testMatchedWorkload() *MatchedWorkload {
	return &MatchedWorkload{
		Name:             "api",
		AllowlistVersion: "7",
		AllowlistDigest:  bytes.Repeat([]byte{0x11}, 32),
	}
}

// goldenMatchedWorkloadDER is the one canonical encoding of
// {v1, "api", "7", 0x11*32} — shared with the JS verifier and TEErminator so
// three parsers cannot drift.
const goldenMatchedWorkloadDER = "302d0201011603617069160137" +
	"04201111111111111111111111111111111111111111111111111111111111111111"

func TestMatchedWorkload_GoldenVector(t *testing.T) {
	ext, err := MarshalMatchedWorkloadExtension(testMatchedWorkload())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ext.Value); got != goldenMatchedWorkloadDER {
		t.Fatalf("DER = %s, want %s", got, goldenMatchedWorkloadDER)
	}
	if ext.Critical {
		t.Fatal("matched-workload extension must be non-critical")
	}
	if !ext.Id.Equal(OIDMatchedWorkload) {
		t.Fatalf("OID = %v", ext.Id)
	}

	der, _ := hex.DecodeString(goldenMatchedWorkloadDER)
	m, err := UnmarshalMatchedWorkload(der)
	if err != nil {
		t.Fatal(err)
	}
	want := testMatchedWorkload()
	if m.Name != want.Name || m.AllowlistVersion != want.AllowlistVersion || !bytes.Equal(m.AllowlistDigest, want.AllowlistDigest) {
		t.Fatalf("round-trip mismatch: %+v", m)
	}
}

func TestMatchedWorkload_MarshalRejectsInvalid(t *testing.T) {
	valid := testMatchedWorkload()
	for name, mutate := range map[string]func(*MatchedWorkload){
		"empty name":             func(m *MatchedWorkload) { m.Name = "" },
		"name over 63 bytes":     func(m *MatchedWorkload) { m.Name = strings.Repeat("a", 64) },
		"name with comma":        func(m *MatchedWorkload) { m.Name = "a,b" },
		"name with leading dot":  func(m *MatchedWorkload) { m.Name = ".api" },
		"name with slash":        func(m *MatchedWorkload) { m.Name = "a/b" },
		"empty version":          func(m *MatchedWorkload) { m.AllowlistVersion = "" },
		"version zero":           func(m *MatchedWorkload) { m.AllowlistVersion = "0" },
		"version leading zero":   func(m *MatchedWorkload) { m.AllowlistVersion = "01" },
		"version non-decimal":    func(m *MatchedWorkload) { m.AllowlistVersion = "1a" },
		"version over 20 digits": func(m *MatchedWorkload) { m.AllowlistVersion = "1" + strings.Repeat("0", 20) },
		"digest short":           func(m *MatchedWorkload) { m.AllowlistDigest = m.AllowlistDigest[:31] },
		"digest long":            func(m *MatchedWorkload) { m.AllowlistDigest = append(m.AllowlistDigest, 0x11) },
		"digest nil":             func(m *MatchedWorkload) { m.AllowlistDigest = nil },
	} {
		t.Run(name, func(t *testing.T) {
			m := *valid
			m.AllowlistDigest = append([]byte(nil), valid.AllowlistDigest...)
			mutate(&m)
			if _, err := MarshalMatchedWorkloadExtension(&m); err == nil {
				t.Fatal("marshal accepted an invalid value")
			}
		})
	}

	// The 63-byte boundary itself is legal.
	m := *valid
	m.Name = strings.Repeat("a", 63)
	if _, err := MarshalMatchedWorkloadExtension(&m); err != nil {
		t.Fatalf("63-byte name rejected: %v", err)
	}
}

func TestMatchedWorkload_UnmarshalRejectsBoundaries(t *testing.T) {
	golden, _ := hex.DecodeString(goldenMatchedWorkloadDER)

	// Extra trailing field inside the sequence.
	extraField, err := asn1.Marshal(struct {
		FormatVersion    int
		Name             string `asn1:"ia5"`
		AllowlistVersion string `asn1:"ia5"`
		AllowlistDigest  []byte
		Extra            int
	}{1, "api", "7", bytes.Repeat([]byte{0x11}, 32), 5})
	if err != nil {
		t.Fatal(err)
	}

	// Version 2 with otherwise valid fields.
	v2, err := asn1.Marshal(matchedWorkloadASN1{2, "api", "7", bytes.Repeat([]byte{0x11}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	// Non-minimal outer length (long form where short form is canonical).
	nonMinimal := append([]byte{0x30, 0x81, golden[1]}, golden[2:]...)

	// UTF8String tag where IA5String is required.
	utf8Name := append([]byte(nil), golden...)
	utf8Name[5] = 0x0c // tag of the name field ("api")

	for name, der := range map[string][]byte{
		"empty":                  {},
		"truncated":              golden[:len(golden)-1],
		"trailing bytes":         append(append([]byte(nil), golden...), 0x00),
		"extra sequence field":   extraField,
		"unknown format version": v2,
		"non-minimal length":     nonMinimal,
		"wrong string tag":       utf8Name,
		"not a sequence":         {0x02, 0x01, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalMatchedWorkload(der); err == nil {
				t.Fatal("unmarshal accepted a rejected boundary")
			}
		})
	}
}

// selfSignedWithExts mints a self-signed certificate carrying the given
// extensions, for parser tests. Nothing here vouches for the extensions —
// which is exactly what CheckWorkloadPin's chain requirement is about.
func selfSignedWithExts(t *testing.T, exts ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestMatchedWorkloadFromCert(t *testing.T) {
	ext, err := MarshalMatchedWorkloadExtension(testMatchedWorkload())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("absent is nil, no error", func(t *testing.T) {
		m, err := MatchedWorkloadFromCert(selfSignedWithExts(t))
		if err != nil || m != nil {
			t.Fatalf("m = %v, err = %v", m, err)
		}
	})
	t.Run("present parses", func(t *testing.T) {
		m, err := MatchedWorkloadFromCert(selfSignedWithExts(t, ext))
		if err != nil {
			t.Fatal(err)
		}
		if m == nil || m.Name != "api" {
			t.Fatalf("m = %+v", m)
		}
	})
	t.Run("duplicate fails closed", func(t *testing.T) {
		// x509.CreateCertificate refuses to mint a duplicate, so drive the
		// parser directly with a hand-built certificate value.
		dup := &x509.Certificate{Extensions: []pkix.Extension{ext, ext}}
		if _, err := MatchedWorkloadFromCert(dup); err == nil {
			t.Fatal("duplicate extension accepted")
		}
	})
	t.Run("malformed fails closed", func(t *testing.T) {
		bad := ext
		bad.Value = append([]byte(nil), ext.Value...)
		bad.Value[0] = 0x31
		if _, err := MatchedWorkloadFromCert(selfSignedWithExts(t, bad)); err == nil {
			t.Fatal("malformed extension accepted")
		}
	})
}

func TestCheckWorkloadPin(t *testing.T) {
	ext, err := MarshalMatchedWorkloadExtension(testMatchedWorkload())
	if err != nil {
		t.Fatal(err)
	}
	stamped := selfSignedWithExts(t, ext)
	unstamped := selfSignedWithExts(t)

	if err := CheckWorkloadPin(stamped, ""); err != nil {
		t.Fatalf("empty pin must be a no-op: %v", err)
	}
	if err := CheckWorkloadPin(stamped, "api"); err != nil {
		t.Fatalf("matching pin failed: %v", err)
	}
	if err := CheckWorkloadPin(stamped, "other"); err == nil {
		t.Fatal("mismatched pin accepted")
	}
	if err := CheckWorkloadPin(unstamped, "api"); err == nil {
		t.Fatal("pin against an unstamped leaf accepted")
	}
	bad := ext
	bad.Value = ext.Value[:4]
	if err := CheckWorkloadPin(selfSignedWithExts(t, bad), "api"); err == nil {
		t.Fatal("pin against a malformed stamp accepted")
	}
}

func TestPeerMatchedWorkload(t *testing.T) {
	ext, err := MarshalMatchedWorkloadExtension(testMatchedWorkload())
	if err != nil {
		t.Fatal(err)
	}
	leaf := selfSignedWithExts(t, ext)

	if _, err := PeerMatchedWorkload(tls.ConnectionState{}); err == nil {
		t.Fatal("no peer certificate accepted")
	}
	if _, err := PeerMatchedWorkload(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}); err == nil {
		t.Fatal("unverified chain accepted — the stamp is CA-vouched")
	}
	m, err := PeerMatchedWorkload(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.Name != "api" {
		t.Fatalf("m = %+v", m)
	}
}
