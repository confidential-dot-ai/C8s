package armtls

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// testMeasurement is the launch measurement a test pins so the evidence path
// reaches the check the test names rather than [ErrUnpinned].
var testMeasurement = bytes.Repeat([]byte{0x11}, SNPMeasurementSize)

// pinnedPolicy pins testMeasurement and verifies evidence through url.
func pinnedPolicy(url string) *VerifyPolicy {
	return &VerifyPolicy{AttestationApiURL: url, Policy: remote.Policy{Measurements: [][]byte{testMeasurement}}}
}

// pinnedStub is an attestation-api stub whose verdict reports testMeasurement,
// so pinnedPolicy admits the peer it answers for.
func pinnedStub(t *testing.T) *mockapi.Stub {
	t.Helper()
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(testMeasurement)))
	return stub
}

// Every evidence path refuses a policy that names no guest: registers and a TCB
// floor narrow a guest a launch measurement or image pin already named, so on
// their own they admit any attested TEE.
func TestEvidencePathsRefuseAnUnpinnedPolicy(t *testing.T) {
	key, att, cert := testAttestedCert(t, nil)
	paths := map[string]func(*VerifyPolicy) error{
		"NewClientTLSConfig": func(policy *VerifyPolicy) error {
			_, _, err := NewClientTLSConfig(&ClientConfig{Policy: policy})
			return err
		},
		"NewServerTLSConfig": func(policy *VerifyPolicy) error {
			cfg := testServerConfig()
			cfg.ClientPolicy = policy
			_, _, err := NewServerTLSConfig(cfg)
			return err
		},
		"VerifyCert": func(policy *VerifyPolicy) error {
			_, err := VerifyCert(cert, policy, nil)
			return err
		},
		"VerifyAttestation": func(policy *VerifyPolicy) error {
			_, err := VerifyAttestation(&key.PublicKey, att, policy, nil)
			return err
		},
	}
	policies := map[string]*VerifyPolicy{
		"no pins": {AttestationApiURL: "http://unused.invalid"},
		"registers only": {
			AttestationApiURL: "http://unused.invalid",
			Policy:            remote.Policy{Registers: map[int][]byte{3: testMeasurement}},
		},
	}
	for path, call := range paths {
		for shape, policy := range policies {
			t.Run(path+" "+shape, func(t *testing.T) {
				if err := call(policy); !errors.Is(err, ErrUnpinned) {
					t.Fatalf("err = %v, want errors.Is ErrUnpinned", err)
				}
			})
		}
	}
}

func TestDynamicClientStartsEmptyAndChecksCurrentPolicy(t *testing.T) {
	stub := pinnedStub(t)
	key, _, cert := testAttestedCert(t, nil)
	empty := &VerifyPolicy{AttestationApiURL: stub.URL()}
	current := empty
	var currentErr error
	cfg := &ClientConfig{
		Policy:  empty,
		Current: func() (*VerifyPolicy, error) { return current, currentErr },
	}
	tlsConfig, _, err := NewClientTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}}}
	server.StartTLS()
	defer server.Close()
	client := HTTPClient(tlsConfig)
	defer client.CloseIdleConnections()
	check := func() error {
		client.CloseIdleConnections()
		response, err := client.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		return err
	}
	if err := check(); !errors.Is(err, ErrUnpinned) || len(stub.VerifyRequests()) != 0 {
		t.Fatalf("empty current policy = %v, verification requests = %d", err, len(stub.VerifyRequests()))
	}
	launch := bytes.Repeat([]byte{0x22}, 32)
	current = Pins{Images: []remote.ImagePin{{
		Name:             "worker",
		Digest:           testMeasurement,
		LaunchFileDigest: launch,
	}}}.VerifyPolicy(stub.URL())
	for _, tc := range []struct {
		name          string
		image, launch []byte
		accept        bool
	}{
		{
			name:   "admitted",
			image:  testMeasurement,
			launch: launch,
			accept: true,
		},
		{
			name:   "wrong image",
			image:  bytes.Repeat([]byte{0x33}, SNPMeasurementSize),
			launch: launch,
		},
		{
			name:   "wrong launch",
			image:  testMeasurement,
			launch: bytes.Repeat([]byte{0x44}, 32),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := mockapi.PassingVerdict(hex.EncodeToString(tc.image))
			verdict.Claims.InitData = tc.launch
			stub.SetVerdict(verdict)
			err := check()
			if (err == nil) != tc.accept {
				t.Fatalf("handshake = %v, want accepted %v", err, tc.accept)
			}
		})
	}
	requests := len(stub.VerifyRequests())
	for _, policy := range []*VerifyPolicy{empty, nil} {
		current = policy
		if err := check(); err == nil {
			t.Fatal("empty or nil replacement policy admitted a peer")
		}
	}
	current = pinnedPolicy(stub.URL())
	currentErr = errors.New("state unavailable")
	if err := check(); !errors.Is(err, currentErr) || len(stub.VerifyRequests()) != requests {
		t.Fatalf("failed policy = %v, verification requests = %d", err, len(stub.VerifyRequests()))
	}
	cfg.Policy = nil
	if _, _, err := NewClientTLSConfig(cfg); err == nil {
		t.Fatal("dynamic client accepted nil initial Policy")
	}
}
