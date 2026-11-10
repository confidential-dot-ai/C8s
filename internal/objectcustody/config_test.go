package objectcustody

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"gopkg.in/yaml.v3"
)

const testTCB uint64 = 0x0201000000000101

func testWire(t *testing.T) wire {
	t.Helper()
	operator, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&operator.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	nodes, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name: "nodes",
			Digest: bytes.Repeat(
				[]byte{0x31},
				48,
			),
			Anchor: public,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	launch, err := yaml.Marshal(map[string]any{
		"schemaVersion":      "c8s-cds/v1",
		"clusterID":          "custody-test",
		"operatorPublicKeys": string(public),
		"workloads":          `{"schema":"c8s.allowlist/v1","workloads":{}}`,
		"nodes":              string(nodes),
		"nodeCIDRs":          []string{"10.42.0.0/24"},
		"objectState": map[string]any{
			"bucket":              "cds-custody-test",
			"key":                 "clusters/custody-test/current",
			"region":              "us-east-2",
			"expectedBucketOwner": "123456789012",
			"recoveryAuthority":   AuthorityPlaceholder,
			"snpMinTCB":           map[string]uint8{"bootloader": 12, "tee": 0, "snp": 28, "microcode": 28},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := wire{
		SchemaVersion: SchemaVersion,
		CDSTemplate:   string(launch),
		CDSImages: []string{
			`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds-snp","measurement":"` + strings.Repeat(
				"11",
				48,
			) + `"}]}`,
			`{"schema_version":"1","tee":"tdx","measurements":[{"name":"cds-tdx","mrtd":"` + strings.Repeat(
				"22",
				48,
			) + `","rtmr":[null,"` + strings.Repeat(
				"44",
				48,
			) + `","` + strings.Repeat(
				"55",
				48,
			) + `",null]}]}`,
		},
		OwnerClientCA: testOwner(
			t,
			nil,
		),
	}
	guestSVN, tcb := uint32(0), testTCB
	input.Derivation.GuestSVN, input.Derivation.TCB = &guestSVN, &tcb
	return input
}

func testOwner(
	t *testing.T,
	mutate func(*x509.Certificate),
) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic independent owner"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	if mutate != nil {
		mutate(cert)
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		cert,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
}

func encodeWire(
	t *testing.T,
	input wire,
) []byte {
	t.Helper()
	document, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	config, err := Parse(encodeWire(
		t,
		testWire(t),
	))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestCompleteBindsExactLaunchWithoutChangingCustody(t *testing.T) {
	input := testWire(t)
	document := encodeWire(
		t,
		input,
	)
	config, err := Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	launch, parsed, images, err := config.Complete(public)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(
		input.CDSTemplate,
		AuthorityPlaceholder,
		base64.StdEncoding.EncodeToString(public),
		1,
	)
	if string(launch) != want || !bytes.Equal(
		parsed.ObjectState.RecoveryAuthority,
		public,
	) || len(images) != 2 {
		t.Fatal("completed launch changed more than the authority or lost its image policy")
	}
	for _, image := range images {
		if !bytes.Equal(
			image.LaunchFile,
			launch,
		) || image.Anchor != nil || image.LaunchFileDigest != nil {
			t.Fatal("image was not bound to the exact completed launch")
		}
	}
	if !bytes.Equal(
		config.Document(),
		document,
	) || config.Parameters() != (Parameters{
		GuestSVN: 0,
		TCB:      testTCB,
	}) {
		t.Fatal("completion changed the measured custody document or fixed parameters")
	}
	clear(document)
	clear(config.Document())
	clear(config.OwnerCA().Raw)
	clear(launch)
	clear(images[0].Digest)
	clear(images[1].Registers[1])
	clear(images[1].LaunchFile)
	second, _, secondImages, err := config.Complete(public)
	if err != nil || string(second) != want || secondImages[0].Digest[0] != 0x11 || secondImages[1].Registers[1][0] != 0x44 || config.OwnerCA() == nil {
		t.Fatal("caller-owned output mutated the measured configuration")
	}
	for _, invalid := range []ed25519.PublicKey{
		nil,
		make(
			[]byte,
			31,
		),
		make(
			[]byte,
			32,
		),
	} {
		if _, _, _, err := config.Complete(invalid); err == nil {
			t.Fatal("accepted an invalid or placeholder authority")
		}
	}
}

func TestCompletedTDXImageEnforcesLaunchAndStableRegisters(t *testing.T) {
	config := testConfig(t)
	launch, _, images, err := config.Complete(ed25519.PublicKey(bytes.Repeat(
		[]byte{0x62},
		ed25519.PublicKeySize,
	)))
	if err != nil {
		t.Fatal(err)
	}
	changedLaunch := append(
		bytes.Clone(launch),
		'\n',
	)
	for _, test := range []struct {
		name      string
		launch    []byte
		registers map[string]string
		want      error
	}{
		{
			name:   "completed launch",
			launch: launch,
		},
		{
			name:   "uncompleted template",
			launch: config.template,
			want:   remote.ErrLaunchFileNotAllowed,
		},
		{
			name:   "different launch bytes",
			launch: changedLaunch,
			want:   remote.ErrLaunchFileNotAllowed,
		},
		{
			name:   "different RTMR1",
			launch: launch,
			registers: map[string]string{"rtmr_1": strings.Repeat(
				"66",
				48,
			)},
			want: remote.ErrRegistersNotAllowed,
		},
		{
			name:   "different RTMR2",
			launch: launch,
			registers: map[string]string{"rtmr_2": strings.Repeat(
				"66",
				48,
			)},
			want: remote.ErrRegistersNotAllowed,
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				binding := runtimemeasure.Seed(test.launch)
				matchedReportData := true
				// These synthetic claims model the result after hardware signature
				// and freshness verification, which precedes EnforceImages.
				response := remote.VerifyResponse{Result: teetypes.VerificationResult{
					SignatureValid:  true,
					Platform:        teetypes.PlatformTDX,
					ReportDataMatch: &matchedReportData,
					Claims: teetypes.Claims{
						LaunchDigest: strings.Repeat(
							"22",
							48,
						),
						PlatformData: map[string]any{
							"rtmr_1": strings.Repeat(
								"44",
								48,
							),
							"rtmr_2": strings.Repeat(
								"55",
								48,
							),
							"rtmr_3": hex.EncodeToString(binding[:]),
						},
					},
				}}
				for register, value := range test.registers {
					response.Result.Claims.PlatformData[register] = value
				}
				if err := remote.EnforceImages(
					response,
					images,
					teetypes.PlatformTDX,
				); !errors.Is(
					err,
					test.want,
				) {
					t.Fatalf(
						"EnforceImages = %v, want %v",
						err,
						test.want,
					)
				}
			},
		)
	}
}

func TestConfigurationRejectsAmbiguousOrWeakenedPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*wire)
	}{
		{
			"version",
			func(w *wire) { w.SchemaVersion = "future" },
		},
		{
			"missing SVN",
			func(w *wire) { w.Derivation.GuestSVN = nil },
		},
		{
			"missing TCB",
			func(w *wire) { w.Derivation.TCB = nil },
		},
		{
			"zero TCB",
			func(w *wire) { value := uint64(0); w.Derivation.TCB = &value },
		},
		{
			"nonplaceholder authority",
			func(w *wire) {
				w.CDSTemplate = strings.Replace(
					w.CDSTemplate,
					AuthorityPlaceholder,
					base64.StdEncoding.EncodeToString(bytes.Repeat(
						[]byte{1},
						32,
					)),
					1,
				)
			},
		},
		{
			"duplicate placeholder",
			func(w *wire) { w.CDSTemplate += "# " + AuthorityPlaceholder + "\n" },
		},
		{
			"unknown CDS field",
			func(w *wire) { w.CDSTemplate += "ignored: true\n" },
		},
		{
			"no images",
			func(w *wire) { w.CDSImages = nil },
		},
		{
			"repeated family",
			func(w *wire) { w.CDSImages[1] = w.CDSImages[0] },
		},
		{
			"empty images",
			func(w *wire) { w.CDSImages = []string{`{"schema_version":"1","tee":"sev-snp","measurements":[]}`} },
		},
		{
			"unknown image field",
			func(w *wire) {
				w.CDSImages[0] = strings.Replace(
					w.CDSImages[0],
					`"name":`,
					`"ignored":true,"name":`,
					1,
				)
			},
		},
		{
			"partial TDX identity",
			func(w *wire) {
				w.CDSImages[1] = `{"schema_version":"1","tee":"tdx","measurements":[{"name":"cds","mrtd":"` + strings.Repeat(
					"11",
					48,
				) + `"}]}`
			},
		},
		{
			"missing RTMR1",
			func(w *wire) {
				w.CDSImages[1] = strings.Replace(
					w.CDSImages[1],
					`"`+strings.Repeat(
						"44",
						48,
					)+`"`,
					`null`,
					1,
				)
			},
		},
		{
			"missing RTMR2",
			func(w *wire) {
				w.CDSImages[1] = strings.Replace(
					w.CDSImages[1],
					`"`+strings.Repeat(
						"55",
						48,
					)+`"`,
					`null`,
					1,
				)
			},
		},
		{
			"prebound RTMR3",
			func(w *wire) {
				w.CDSImages[1] = strings.Replace(
					w.CDSImages[1],
					`,null]`,
					`,"`+strings.Repeat(
						"00",
						48,
					)+`"]`,
					1,
				)
			},
		},
		{
			"prebound launch",
			func(w *wire) {
				w.CDSImages[0] = strings.Replace(
					strings.Replace(
						w.CDSImages[0],
						`"1"`,
						`"2"`,
						1,
					),
					`"name":`,
					`"launch_file":"unapproved","name":`,
					1,
				)
			},
		},
		{
			"prebound hash",
			func(w *wire) {
				w.CDSImages[0] = strings.Replace(
					strings.Replace(
						w.CDSImages[0],
						`"1"`,
						`"2"`,
						1,
					),
					`"name":`,
					`"launch_file_digest":"`+strings.Repeat(
						"99",
						32,
					)+`","name":`,
					1,
				)
			},
		},
		{
			"no owner",
			func(w *wire) { w.OwnerClientCA = "" },
		},
		{
			"extra certificate",
			func(w *wire) { w.OwnerClientCA += w.OwnerClientCA },
		},
		{
			"trailing secret",
			func(w *wire) { w.OwnerClientCA += "PRIVATE MATERIAL" },
		},
		{
			"leaf owner",
			func(w *wire) {
				w.OwnerClientCA = testOwner(
					t,
					func(c *x509.Certificate) { c.IsCA = false },
				)
			},
		},
		{
			"expired owner",
			func(w *wire) {
				w.OwnerClientCA = testOwner(
					t,
					func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) },
				)
			},
		},
		{
			"wrong owner purpose",
			func(w *wire) {
				w.OwnerClientCA = testOwner(
					t,
					func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
				)
			},
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				input := testWire(t)
				test.mutate(&input)
				if _, err := Parse(encodeWire(
					t,
					input,
				)); err == nil {
					t.Fatal("accepted invalid custody configuration")
				}
			},
		)
	}
	document := encodeWire(
		t,
		testWire(t),
	)
	for _, bad := range [][]byte{
		append(
			bytes.Clone(document),
			[]byte("ignored: true\n")...,
		),
		append(
			bytes.Clone(document),
			[]byte("schemaVersion: c8s-cds-custody/v1\n")...,
		),
		append(
			bytes.Clone(document),
			[]byte("---\n{}")...,
		),
		bytes.Repeat(
			[]byte{'x'},
			1<<20+1,
		),
	} {
		if _, err := Parse(bad); err == nil {
			t.Fatal("accepted ambiguous, unknown or oversized document")
		}
	}
	var value any
	if err := yaml.Unmarshal(
		document,
		&value,
	); err != nil {
		t.Fatal(err)
	}
	jsonDocument, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(jsonDocument); err != nil {
		t.Fatalf(
			"JSON representation rejected: %v",
			err,
		)
	}
}
