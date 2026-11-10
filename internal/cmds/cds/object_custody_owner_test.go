package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/objectcustody"
	"github.com/confidential-dot-ai/c8s/internal/objectstate"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"gopkg.in/yaml.v3"
)

type ownerFixture struct {
	owner    *objectCustodyOwner
	info     objectCustodyInfo
	output   bytes.Buffer
	issued   []objectcustody.SessionPurpose
	requests []string
	clients  int
	post     func(*http.Request) (*http.Response, error)
}

func newOwnerFixture(t *testing.T) *ownerFixture {
	t.Helper()
	_, public := operatorKeyPair(t)
	var template map[string]any
	if err := yaml.Unmarshal(
		measuredDocument(
			t,
			cluster{operatorPEM: public},
		),
		&template,
	); err != nil {
		t.Fatal(err)
	}
	template["objectState"] = map[string]any{
		"bucket":              "cds-owner-test",
		"key":                 "clusters/lane/current",
		"region":              "us-east-2",
		"expectedBucketOwner": "123456789012",
		"recoveryAuthority":   objectcustody.AuthorityPlaceholder,
		"snpMinTCB":           map[string]uint8{"bootloader": 12, "tee": 0, "snp": 28, "microcode": 28},
	}
	launch, err := yaml.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	ownerCA, cert, key := ownerClientIdentity(t)
	pins := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"custody","measurement":"` + strings.Repeat(
		"11",
		48,
	) + `"}]}`
	raw, err := yaml.Marshal(map[string]any{
		"schemaVersion": objectcustody.SchemaVersion,
		"cdsTemplate":   string(launch),
		"cdsImages":     []string{pins},
		"ownerClientCA": string(ownerCA),
		"derivation": map[string]any{
			"guestSVN": 0,
			"tcb":      uint64(0x0201000000000101),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := objectcustody.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	authority, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	completed, measured, _, err := document.Complete(authority)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		"custody.yaml": raw,
		"pins.json":    []byte(pins),
		"owner.crt":    cert,
		"owner.key":    key,
		"cds.yaml":     completed,
	} {
		if err := os.WriteFile(
			filepath.Join(
				dir,
				name,
			),
			data,
			0600,
		); err != nil {
			t.Fatal(err)
		}
	}
	options := objectCustodyOwnerOptions{
		origin: "https://custody.invalid",
		document: filepath.Join(
			dir,
			"custody.yaml",
		),
		pins: filepath.Join(
			dir,
			"pins.json",
		),
		certificate: filepath.Join(
			dir,
			"owner.crt",
		),
		key: filepath.Join(
			dir,
			"owner.key",
		),
		completed: filepath.Join(
			dir,
			"cds.yaml",
		),
		profile: "owner-test",
		role:    "arn:aws:iam::123456789012:role/custody-test",
		origins: []string{
			"https://cds-a.invalid",
			"https://cds-b.invalid",
			"https://cds-c.invalid",
		},
	}
	owner, err := loadObjectCustodyOwner(options)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &ownerFixture{
		owner: owner,
		info: objectCustodyInfo{
			Launch: completed,
			Identity: objectRecoveryIdentity(config{
				measured:     measured,
				measuredFile: completed,
			}),
		},
	}
	owner.output, owner.diagnostics = &fixture.output, &fixture.output
	owner.client = func(context.Context) (*http.Client, error) {
		fixture.clients++
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			fixture.requests = append(
				fixture.requests,
				request.URL.Path,
			)
			if request.URL.Path == objectCustodyLaunchPath {
				return ownerResponse(
					t,
					http.StatusOK,
					fixture.info,
				), nil
			}
			if request.GetBody != nil {
				t.Fatal("secret-bearing request permits automatic body replay")
			}
			if fixture.post != nil {
				return fixture.post(request)
			}
			return ownerResponse(
				t,
				http.StatusOK,
				objectCustodyResult{CAKeyID: "public-ca-key-id"},
			), nil
		})}, nil
	}
	owner.newIssuer = func(
		_ context.Context,
		storage objectstate.S3Config,
	) (objectCustodyIssue, error) {
		if len(fixture.requests) == 0 || fixture.requests[len(fixture.requests)-1] != objectCustodyLaunchPath || storage.Key != "clusters/lane/current" || storage.ExpectedOwner != "123456789012" {
			t.Fatal("issued a session before checking launch or for another storage authority")
		}
		return func(
			_ context.Context,
			purpose objectcustody.SessionPurpose,
		) (objectstate.TemporaryCredentials, error) {
			fixture.issued = append(
				fixture.issued,
				purpose,
			)
			return objectstate.TemporaryCredentials{
				AccessKeyID:     "synthetic-access",
				SecretAccessKey: "synthetic-secret-never-output",
				SessionToken:    "synthetic-token-never-output",
				ExpiresAt:       time.Now().Add(15*time.Minute + time.Duration(fixture.clients)*time.Minute),
			}, nil
		}, nil
	}
	return fixture
}

func ownerClientIdentity(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(
		elliptic.P256(),
		rand.Reader,
	)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "owner"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(
		rand.Reader,
		ca,
		ca,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "owner-client"},
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		leaf,
		ca,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caDER,
		}), pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}), pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})
}

func ownerResponse(
	t *testing.T,
	status int,
	value any,
) *http.Response {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(data)),
		Header:     make(http.Header),
	}
}

func TestObjectCustodyOwnerPinsBeforeIssuingAndNeverRetriesInitialization(t *testing.T) {
	for _, mismatch := range []string{
		"launch",
		"identity",
	} {
		t.Run(
			mismatch,
			func(t *testing.T) {
				f := newOwnerFixture(t)
				if mismatch == "launch" {
					f.owner.completed = append(
						bytes.Clone(f.info.Launch),
						'\n',
					)
				} else {
					f.info.Identity.StorageSHA256 = strings.Repeat(
						"00",
						32,
					)
				}
				if err := f.owner.run(
					context.Background(),
					"initialize",
				); err == nil || len(f.issued) != 0 || len(f.requests) != 1 {
					t.Fatal("unmatched custodian obtained credentials or initialization")
				}
			},
		)
	}
	f := newOwnerFixture(t)
	f.owner.options.renew = true
	f.post = func(request *http.Request) (*http.Response, error) {
		var received objectCustodyRequest
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		if request.URL.Path != objectCustodyInitializePath || received.Writer != nil || len(received.Origins) != 0 || received.ConfigSHA256 != f.info.Identity.ConfigSHA256 {
			t.Fatal("initialization issued recovery credentials or missed the completed-launch pin")
		}
		return ownerResponse(
			t,
			http.StatusServiceUnavailable,
			"synthetic-secret-never-output",
		), nil
	}
	err := f.owner.run(
		context.Background(),
		"initialize",
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"outcome unknown",
	) || len(f.requests) != 2 || !reflect.DeepEqual(
		f.issued,
		[]objectcustody.SessionPurpose{objectcustody.SessionInitializer},
	) {
		t.Fatal("initialization was retried or its unknown outcome was hidden")
	}
	if strings.Contains(
		f.output.String(),
		"secret",
	) || strings.Contains(
		err.Error(),
		"synthetic-secret",
	) {
		t.Fatal("error response or credential material escaped into output")
	}
}

func TestObjectCustodyOwnerRenewalOnlyProvisionsWithFreshSessions(t *testing.T) {
	f := newOwnerFixture(t)
	f.owner.options.renew = true
	posts, waits := 0, 0
	f.post = func(request *http.Request) (*http.Response, error) {
		posts++
		var received objectCustodyRequest
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		if request.URL.Path != objectCustodyProvisionPath || received.Writer == nil || !reflect.DeepEqual(
			received.Origins,
			f.owner.options.origins,
		) {
			t.Fatal("renewal used initialization or lost replica isolation")
		}
		if posts == 1 {
			return ownerResponse(
				t,
				http.StatusServiceUnavailable,
				"synthetic-token-never-output",
			), nil
		}
		var replicas []objectCustodyReplica
		for _, origin := range received.Origins {
			replicas = append(
				replicas,
				objectCustodyReplica{
					Origin: origin,
					Ready:  true,
				},
			)
		}
		return ownerResponse(
			t,
			http.StatusOK,
			objectCustodyResult{Ready: replicas},
		), nil
	}
	f.owner.wait = func(
		_ context.Context,
		delay time.Duration,
	) error {
		waits++
		if waits == 1 {
			if delay < time.Second || delay >= 2*time.Second {
				t.Fatal("unbounded first retry delay")
			}
			return nil
		}
		if delay < 5*time.Minute || delay >= 5*time.Minute+30*time.Second {
			t.Fatal("renewal did not use its bounded five-minute interval")
		}
		return context.Canceled
	}
	if err := f.owner.run(
		context.Background(),
		"provision",
	); !errors.Is(
		err,
		context.Canceled,
	) || f.clients != 2 || posts != 2 {
		t.Fatal("renewal did not reconnect, retry boundedly and stop on cancellation")
	}
	if !reflect.DeepEqual(
		f.issued,
		[]objectcustody.SessionPurpose{
			objectcustody.SessionReader,
			objectcustody.SessionWriter,
			objectcustody.SessionReader,
			objectcustody.SessionWriter,
		},
	) || strings.Contains(
		f.output.String(),
		"synthetic-",
	) {
		t.Fatal("renewal issued the wrong session scope or disclosed credentials")
	}
	f = newOwnerFixture(t)
	f.owner.readerExpiry = time.Now().Add(time.Hour)
	if err := f.owner.run(
		context.Background(),
		"provision",
	); err == nil || len(f.requests) != 1 {
		t.Fatal("resent a different grant with non-increasing expiry")
	}
}

func TestObjectCustodyOwnerLaunchAndInputBoundaries(t *testing.T) {
	f := newOwnerFixture(t)
	if err := f.owner.run(
		context.Background(),
		"launch",
	); err != nil || !bytes.Equal(
		f.output.Bytes(),
		f.info.Launch,
	) || len(f.issued) != 0 {
		t.Fatal("public launch discovery mutated state or returned another launch")
	}
	f.owner.options.output = filepath.Join(
		t.TempDir(),
		"public-cds.yaml",
	)
	if err := f.owner.run(
		context.Background(),
		"launch",
	); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.run(
		context.Background(),
		"launch",
	); err == nil {
		t.Fatal("public launch silently overwrote an existing pin")
	}
	for _, origins := range [][]string{
		nil,
		{"http://cds.invalid"},
		{
			"https://cds.invalid",
			"https://cds.invalid",
		},
		make(
			[]string,
			17,
		),
	} {
		f := newOwnerFixture(t)
		f.owner.options.origins = origins
		if err := f.owner.run(
			context.Background(),
			"provision",
		); err == nil || f.clients != 0 || len(f.issued) != 0 {
			t.Fatal("invalid origins reached the custodian or issuer")
		}
	}
	f = newOwnerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.owner.run(
		ctx,
		"initialize",
	); !errors.Is(
		err,
		context.Canceled,
	) || f.clients != 0 {
		t.Fatal("canceled command reached initialization")
	}
	if err := waitObjectCustodyRenewal(
		ctx,
		time.Hour,
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatal("renewal timer ignored cancellation")
	}
	commands := newObjectCustodyOwnerCommands()
	for _, command := range commands {
		if (command.Name() == "initialize" && command.Flags().Lookup("renew") != nil) || command.Flags().Lookup("insecure") != nil {
			t.Fatal("owner CLI exposed initialization renewal or TLS bypass")
		}
	}
}

func TestObjectCustodyOwnerTLSBindsNativeImageConfigAndOwner(t *testing.T) {
	f := newOwnerFixture(t)
	key, _, err := armtls.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := armtls.CreateAttestedCert(
		key,
		&armtls.Attestation{
			Family: armtls.TEETypeSEVSNP,
			Report: make(
				[]byte,
				armtls.SNPReportSize,
			),
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat(
		[]byte{0x11},
		48,
	)
	configHash := sha256.Sum256(f.owner.document.Document())
	calls := 0
	verdict := errors.New("synthetic attestation rejection")
	verify := func(
		ctx context.Context,
		platform string,
		_ json.RawMessage,
		params localverify.Params,
	) (*teetypes.VerificationResult, error) {
		calls++
		if platform != string(teetypes.PlatformSNP) || len(params.ExpectedReportData) != 48 || !bytes.Equal(
			params.ExpectedInitDataHash,
			configHash[:],
		) || params.AllowDebug || len(params.Measurements) != 1 || !bytes.Equal(
			params.Measurements[0],
			digest,
		) || params.MinTCB == nil || params.MinTCB.Microcode != 28 || params.MinTCB.Snp != 28 || params.MinTCB.Bootloader != 12 {
			t.Fatal("custody verification omitted a native hardware, key, image, config or TCB constraint")
		}
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("attestation verification was unbounded")
		}
		return nil, verdict
	}
	identity, err := tls.LoadX509KeyPair(
		f.owner.options.certificate,
		f.owner.options.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	client := objectCustodyOwnerClient(
		context.Background(),
		f.owner.document,
		[][]byte{digest},
		identity,
		verify,
	)
	transport := client.Transport.(*http.Transport)
	if len(transport.TLSClientConfig.Certificates) != 1 || !transport.DisableKeepAlives || !transport.TLSClientConfig.SessionTicketsDisabled || client.Timeout != 140*time.Second || client.CheckRedirect(
		nil,
		nil,
	) != http.ErrUseLastResponse {
		t.Fatal("owner transport lost client identity, fresh attestations or request bounds")
	}
	if err := transport.TLSClientConfig.VerifyPeerCertificate(
		[][]byte{cert},
		nil,
	); !errors.Is(
		err,
		verdict,
	) || calls != 1 {
		t.Fatal("TLS verification bypassed the attestation rejection")
	}
	envelope, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformAzSNP,
		Evidence: json.RawMessage(`{"hcl_report":"synthetic"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	cloudCert, err := armtls.CreateAttestedCert(
		key,
		&armtls.Attestation{
			Family: armtls.TEETypeSEVSNP,
			Report: envelope,
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.TLSClientConfig.VerifyPeerCertificate(
		[][]byte{cloudCert},
		nil,
	); err == nil || calls != 1 {
		t.Fatal("non-native custodian reached the verifier")
	}
	options := f.owner.options
	if err := os.WriteFile(
		options.pins,
		[]byte(`{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"custody","measurement":"`+strings.Repeat(
			"11",
			48,
		)+`","launch_file":"different"}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := loadObjectCustodyOwner(options); err == nil {
		t.Fatal("accepted custody pins bound to another measured document")
	}
	f = newOwnerFixture(t)
	_, wrongCertificate, wrongKey := ownerClientIdentity(t)
	if err := os.WriteFile(
		f.owner.options.certificate,
		wrongCertificate,
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		f.owner.options.key,
		wrongKey,
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := loadObjectCustodyOwner(f.owner.options); err == nil {
		t.Fatal("accepted an owner identity issued by another CA")
	}
}

func TestObjectCustodyOwnerRequiresRevocationVerdict(t *testing.T) {
	digest := bytes.Repeat(
		[]byte{0x43},
		48,
	)
	params := localverify.Params{
		VerifyParams: teetypes.VerifyParams{
			ExpectedReportData: make(
				[]byte,
				48,
			),
			ExpectedInitDataHash: make(
				[]byte,
				32,
			),
			MinTCB: &teetypes.SnpTcb{Bootloader: 12, Snp: 28, Microcode: 28},
		},
		Measurements: [][]byte{digest},
	}
	matched := true
	result := &teetypes.VerificationResult{
		Platform:           teetypes.PlatformSNP,
		SignatureValid:     true,
		CollateralVerified: true,
		ReportDataMatch:    &matched,
		InitDataMatch:      &matched,
		Claims: teetypes.Claims{
			LaunchDigest: hex.EncodeToString(digest),
			PlatformData: map[string]any{"policy": map[string]any{"migrate_ma": false}},
		},
	}
	var failure error
	verifier, err := objectCustodyNativeVerifier(*params.MinTCB, func(
		ctx context.Context,
		envelope teetypes.AttestationEvidence,
		policy teetypes.VerifyParams,
		options teeverify.Options,
	) (*teetypes.VerificationResult, error) {
		_, bounded := ctx.Deadline()
		if envelope.Platform != teetypes.PlatformSNP || !options.SNP.CheckRevocations || options.SNP.Getter == nil || !bounded || !reflect.DeepEqual(
			policy,
			params.VerifyParams,
		) {
			t.Fatal("owner verifier weakened native revocation, deadlines or binding policy")
		}
		return result, failure
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func() error {
		report := make([]byte, armtls.SNPReportSize)
		report[0x1f0], report[0x1f1], report[0x1f6], report[0x1f7] = 255, 255, 255, 255
		_, err := verifier(
			context.Background(),
			string(teetypes.PlatformSNP),
			json.RawMessage(`{"attestation_report":"`+base64.StdEncoding.EncodeToString(report)+`"}`),
			params,
		)
		return err
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []any{
		map[string]any{"migrate_ma": true},
		map[string]any{"migrate_ma": "false"},
		map[string]any{},
		nil,
	} {
		result.Claims.PlatformData["policy"] = policy
		if err := check(); err == nil {
			t.Fatal("accepted migratable or unproven custody policy")
		}
	}
	result.Claims.PlatformData["policy"] = map[string]any{"migrate_ma": false}
	result.CollateralVerified = false
	if err := check(); err == nil {
		t.Fatal("accepted skipped revocation checks")
	}
	result.CollateralVerified = true
	result.InitDataMatch = nil
	if err := check(); err == nil {
		t.Fatal("accepted an absent launch-configuration verdict")
	}
	result.InitDataMatch = &matched
	result.Claims.LaunchDigest = strings.Repeat(
		"99",
		48,
	)
	if err := check(); err == nil {
		t.Fatal("accepted an unapproved native image")
	}
	failure = errors.New("synthetic CRL unavailable")
	if err := check(); !errors.Is(
		err,
		failure,
	) {
		t.Fatal("collateral failure did not propagate")
	}
}

func TestObjectCustodyOwnerReportsValidatedPartialResults(t *testing.T) {
	for _, alteration := range []string{
		"none",
		"origin",
		"ca",
	} {
		t.Run(
			alteration,
			func(t *testing.T) {
				f := newOwnerFixture(t)
				f.owner.options.origins = []string{
					"https://unavailable.example",
					"https://healthy.example",
				}
				f.post = func(request *http.Request) (*http.Response, error) {
					result := objectCustodyResult{Ready: []objectCustodyReplica{
						{
							Origin: f.owner.options.origins[0],
							Ready:  false,
						},
						{
							Origin: f.owner.options.origins[1],
							Ready:  true,
						},
					}}
					if alteration == "origin" {
						result.Ready[0].Origin = "https://unexpected.example"
					} else if alteration == "ca" {
						result.CAKeyID = "unexpected-ca"
					}
					return ownerResponse(
						t,
						http.StatusServiceUnavailable,
						result,
					), nil
				}
				err := f.owner.run(
					context.Background(),
					"provision",
				)
				if err == nil {
					t.Fatal("partial provisioning was reported as complete")
				}
				if alteration != "none" {
					if f.output.Len() != 0 {
						t.Fatal("unvalidated public result was printed")
					}
					return
				}
				var result objectCustodyResult
				if !errors.Is(
					err,
					errObjectCustodyPartial,
				) || json.Unmarshal(
					f.output.Bytes(),
					&result,
				) != nil || len(result.Ready) != 2 || result.Ready[0].Ready || !result.Ready[1].Ready || result.Ready[0].Origin != f.owner.options.origins[0] || result.Ready[1].Origin != f.owner.options.origins[1] {
					t.Fatal("owner lost the validated per-replica failure and success")
				}
			},
		)
	}
}
