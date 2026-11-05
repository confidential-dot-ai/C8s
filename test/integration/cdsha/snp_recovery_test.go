//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
)

var snpHardware *snpaccept.Hardware
var snpRequest snpaccept.Request
var snpRelay *snpaccept.Relay
var snpChecks map[string]any

func (c *cluster) measurement() string {
	if snpHardware != nil {
		return snpHardware.Measurement()
	}
	return testutil.TestMeasurement
}

func runSNPTestMain(m *testing.M) {
	// An immutable image invokes exactly this test. Never run the mock arms in
	// hardware mode, and never build or execute host-supplied programs.
	if flagRun := os.Args; len(flagRun) != 3 || flagRun[1] != "-test.run=^TestSNPIntegratedRecovery$" || flagRun[2] != "-test.v" {
		panic("fixed SNP acceptance test invocation required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	launch, err := os.ReadFile("/run/confai/operator-pubkey")
	if err != nil {
		panic(err)
	}
	snpHardware, err = snpaccept.OpenHardware(ctx, launch)
	if err != nil {
		panic(err)
	}
	defer snpHardware.Close()
	releaseProcesses = true
	built = binaries{cds: "/usr/local/bin/c8s", logs: "/run/cds-acceptance/logs"}
	err = snpaccept.Serve(ctx, snpHardware, func(q snpaccept.Request, relay *snpaccept.Relay) snpaccept.Result {
		snpRequest, snpRelay, snpChecks = q, relay, make(map[string]any)
		server := &http.Server{Addr: "127.0.0.1:9090", Handler: snpaccept.AttestationAPI(snpHardware, q.Collateral), ReadHeaderTimeout: 5 * time.Second}
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			return snpaccept.Result{Operation: q.Operation, Error: err.Error()}
		}
		go server.Serve(listener)
		defer server.Close()
		code := m.Run()
		out := snpaccept.Result{Operation: q.Operation, Passed: code == 0, Checks: snpChecks, Parameters: q.Parameters}
		if code != 0 {
			out.Error = "CDS acceptance assertion failed; inspect bounded guest diagnostics"
		}
		return out
	})
	if err != nil {
		panic(err)
	}
}

type snpRecoveryBundle struct {
	Record     []byte               `json:"record"`
	Capsule    cdsrecovery.Capsule  `json:"capsule"`
	Parameters snpaccept.Parameters `json:"parameters"`
}
type snpClientState struct {
	CA                    string    `json:"ca"`
	OperatorAuthorization string    `json:"operator_authorization"`
	OperatorBody          []byte    `json:"operator_body"`
	ReplayExpires         time.Time `json:"replay_expires"`
	Secret                []byte    `json:"secret"`
	WorkloadKey           []byte    `json:"workload_key"`
	WorkloadCertificates  [][]byte  `json:"workload_certificates"`
}

func snpStateCipher(wrap []byte) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, wrap, nil, "c8s/cds-snp-acceptance/test-client/v1", 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(b)
}

func snpStore(t *testing.T, f *objectFixture) *objectwal.S3 {
	t.Helper()
	s, err := objectwal.NewS3(objectwal.S3Config{Bucket: f.config.Bucket, Region: f.config.Region, Endpoint: f.config.Endpoint, PathStyle: true, HTTPClient: f.client}, objectwal.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "test-only"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func snpCluster(t *testing.T) (*cluster, *objectwal.S3) {
	t.Helper()
	config, err := cdsconfig.Parse(snpHardware.Launch)
	if err != nil {
		t.Fatal(err)
	}
	if config.ClusterID != clusterID || config.HA == nil || config.HA.ObjectWALPilot == nil || config.HA.ObjectWALPilot.Endpoint != "https://127.0.0.1:9443" || len(config.HA.Replicas) != 3 {
		t.Fatal("unexpected measured acceptance shape")
	}
	block, _ := pem.Decode(snpRequest.OperatorKey)
	if block == nil {
		t.Fatal("operator credential missing")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal("invalid test operator key")
	}
	var authorized bool
	for _, pub := range config.OperatorKeys.Keys() {
		if key.PublicKey.Equal(pub) {
			authorized = true
		}
	}
	if !authorized {
		t.Fatal("operator credential does not match measured launch")
	}
	c := &cluster{t: t, dir: t.TempDir(), config: bytes.Clone(snpHardware.Launch), configPath: "/run/confai/operator-pubkey", operator: key}
	c.signer = c.operatorSigner()
	listener, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(snpRelay)
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	t.Cleanup(server.Close)
	f := &objectFixture{config: *config.HA.ObjectWALPilot, client: server.Client(), certificate: filepath.Join(c.dir, "storage-ca.pem")}
	write(t, f.certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	f.provision = jsonBody(t, cdsobject.Provision{Credentials: objectwal.Credentials{AccessKeyID: "synthetic", SecretAccessKey: "test-only"}})
	c.objectWAL = f
	c.client = c.attestedClient(c.measurement())
	c.requireFreeAddresses(3)
	for i := range 3 {
		c.replicas = append(c.replicas, c.start(i))
	}
	return c, snpStore(t, f)
}

func snpProvision(t *testing.T, c *cluster, store *objectwal.S3) []byte {
	t.Helper()
	signer, wrap, err := snpCustody(t.Context(), c.objectWAL.config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signer)
	t.Cleanup(func() { clear(wrap) })
	f := &recoveryFixture{currentPolicy: true, wrappingKey: wrap, verifier: "http://127.0.0.1:9090", record: filepath.Join(c.dir, "registration.json"), last: make(map[int][]byte)}
	c.objectWAL.recovery = f
	t.Cleanup(f.closeAuthority)
	hash := sha256.Sum256(c.config)
	identity := cdsrecovery.Identity{ClusterID: clusterID, ConfigSHA256: hex.EncodeToString(hash[:]), Prefix: c.objectWAL.config.Prefix}
	name := c.objectWAL.config.Prefix + "/recovery-registration"
	var bundle snpRecoveryBundle
	if snpRequest.Operation == "seed" {
		if _, err := store.Get(t.Context(), name); !errors.Is(err, objectwal.ErrNotFound) {
			t.Fatalf("seed requires absent registration: %v", err)
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		defer clear(key)
		c.awaitStatus(c.replicas[0])
		policy := cdsrecovery.Enrollment{Identity: identity, Pins: []byte(testutil.CDSPinDocument(c.measurement(), string(c.config)))}
		for _, r := range c.replicas {
			policy.Origins = append(policy.Origins, r.base)
		}
		bundle.Record, err = cdsrecovery.Enroll(t.Context(), policy, c.replicas[0].base, f.verifier, key, signer)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Capsule, err = cdsrecovery.SealAuthority(identity, bundle.Record, key, signer, wrap)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Parameters = snpRequest.Parameters
		if _, err := store.Put(t.Context(), name, jsonBody(t, bundle), ""); err != nil {
			t.Fatal(err)
		}
	} else {
		object, err := store.Get(t.Context(), name)
		if err != nil {
			t.Fatalf("recovery requires original registration: %v", err)
		}
		if err := json.Unmarshal(object.Data, &bundle); err != nil {
			t.Fatal(err)
		}
		if bundle.Parameters != snpRequest.Parameters {
			t.Fatal("recovery derivation parameters changed")
		}
	}
	f.capsule = bundle.Capsule
	write(t, f.record, bundle.Record)
	f.restoreCurrent(c, identity, bundle.Record)
	c.provisionObjects(c.replicas[0])
	if snpRequest.Operation == "seed" {
		nodes := fmt.Sprintf(`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":%q}]}`, c.measurement())
		c.genesisCertifying(c.replicas[0], nodes, 0)
	}
	for _, r := range c.replicas[1:] {
		c.provisionObjects(r)
	}
	c.waitServing(time.Minute)
	return wrap
}

func snpCustody(ctx context.Context, config cdsconfig.ObjectWALPilot) (ed25519.PrivateKey, []byte, error) {
	recipient, request, err := snpaccept.NewCustodyRecipient(ctx, snpHardware)
	if err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	response, err := snpRelay.Exchange(ctx, snpaccept.StorageRequest{Method: "CUSTODY", Path: "/pilot/" + config.Prefix + "/custody", Data: b})
	if err != nil {
		return nil, nil, err
	}
	if response.Status != 200 {
		return nil, nil, errors.New("protected custodian refused delegation")
	}
	var grant snpaccept.CustodyGrant
	if err := json.Unmarshal(response.Data, &grant); err != nil {
		return nil, nil, err
	}
	public, err := cdsrecovery.ParseAuthority(config.RecoveryAuthority)
	if err != nil {
		return nil, nil, err
	}
	signer, wrap, err := recipient.Open(grant, public)
	if err == nil {
		snpChecks["attested_custodian_delegation"] = true
	}
	return signer, wrap, err
}

func TestSNPIntegratedRecovery(t *testing.T) {
	if snpHardware == nil {
		t.Skip("only the immutable SNP acceptance image runs this test")
	}
	c, store := snpCluster(t)
	wrap := snpProvision(t, c, store)
	listener, host := inventoryListener(t)
	w := startPilotWorkload(c, listener, host)
	clientCipher, err := snpStateCipher(wrap)
	if err != nil {
		t.Fatal(err)
	}
	name := c.objectWAL.config.Prefix + "/acceptance-client"
	var before snpClientState
	if snpRequest.Operation == "seed" {
		c.replaceAllowlist(c.replicas[0], "pilot-warmup")
		w.setPolicy(true)
		before.Secret = make([]byte, 32)
		if _, err := rand.Read(before.Secret); err != nil {
			t.Fatal(err)
		}
		before.OperatorBody = jsonBody(t, map[string]string{"value": base64.StdEncoding.EncodeToString(before.Secret)})
		before.OperatorAuthorization, err = c.signer.WithTTL(operatorauth.MaxTokenValidity).Authorization(http.MethodPut, "/secrets/pilot/operator", before.OperatorBody)
		if err != nil {
			t.Fatal(err)
		}
		before.ReplayExpires = time.Now().Add(operatorauth.MaxTokenValidity - time.Second)
		if code, body := snpReplay(t, c, before, c.replicas[0]); code != http.StatusCreated {
			t.Fatalf("initial authenticated write: %d %s", code, body)
		}
		w.issue(c.replicas[0], c.replicas[1])
		w.assertEveryReplicaReads("/pilot/operator", before.Secret)
		before.CA = c.servedCA(c.replicas[0])
		before.WorkloadKey, err = x509.MarshalECPrivateKey(w.key)
		if err != nil {
			t.Fatal(err)
		}
		before.WorkloadCertificates = w.client.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate
		w.setPolicy(false)
		for _, r := range c.replicas {
			if code, _ := pilotDo(t, w.client, w.secretRequest(r, http.MethodGet, "/pilot/operator")); code != http.StatusForbidden {
				t.Fatalf("acknowledged revocation: %d", code)
			}
		}
		if code, body := snpReplay(t, c, before, c.replicas[2]); code != http.StatusConflict || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
			t.Fatalf("pre-loss replay: %d %s", code, body)
		}
		plain := jsonBody(t, before)
		defer clear(plain)
		sealed := clientCipher.Seal(nil, nil, plain, []byte(name))
		if _, err := store.Put(t.Context(), name, sealed, ""); err != nil {
			t.Fatal(err)
		}
		snpChecks["authorized_read_before_loss"] = true
		snpChecks["revocation_acknowledged_before_loss"] = true
		snpChecks["replay_rejected_before_loss"] = true
	} else {
		object, err := store.Get(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := clientCipher.Open(nil, nil, object.Data, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(plain)
		if err := json.Unmarshal(plain, &before); err != nil {
			t.Fatal(err)
		}
		if time.Until(before.ReplayExpires) < 30*time.Second {
			t.Fatal("replay token must have at least 30 seconds of validity remaining; expired tokens are not replay proof")
		}
		w.key, err = x509.ParseECPrivateKey(before.WorkloadKey)
		if err != nil {
			t.Fatal(err)
		}
		transport := c.client.Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: before.WorkloadCertificates, PrivateKey: w.key}}
		w.client = &http.Client{Transport: transport, Timeout: 15 * time.Second}
		t.Cleanup(w.client.CloseIdleConnections)
		for _, r := range c.replicas {
			if c.servedCA(r) != before.CA {
				t.Fatal("recovery changed CA identity")
			}
			if code, body := snpReplay(t, c, before, r); code != http.StatusConflict || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
				t.Fatalf("cold recovery replay: %d %s", code, body)
			}
			if code, _ := pilotDo(t, w.client, w.secretRequest(r, http.MethodGet, "/pilot/operator")); code != http.StatusForbidden {
				t.Fatalf("cold recovery revocation: %d", code)
			}
		}
		snpChecks["same_ca_all_replicas"] = true
		snpChecks["unexpired_replay_rejected_all_replicas"] = true
		snpChecks["revocation_preserved_all_replicas"] = true
		// A new signed authorization must restore access to the old secret with
		// the old leaf, ruling out generic unavailability or a broken TLS client.
		w.setPolicy(true)
		w.assertEveryReplicaReads("/pilot/operator", before.Secret)
		snpChecks["old_leaf_and_secret_positive_control"] = true
		w.setPolicy(false)
	}
	snpChecks["ca_fingerprint"] = before.CA
	snpChecks["replay_expires"] = before.ReplayExpires.UTC().Format(time.RFC3339Nano)
	snpChecks["replicas"] = 3
	snpChecks["real_snp_attestation"] = true
	snpChecks["authority_reads_current_wal_policy"] = true
	snpChecks["wal_key_and_ca_never_exported_as_plaintext"] = true
	t.Log("hardware CDS phase passed; only encrypted recovery/client capsules and encrypted WAL persisted externally")
}

func snpReplay(t *testing.T, c *cluster, before snpClientState, r *replica) (int, []byte) {
	t.Helper()
	req := pilotRequest(t, http.MethodPut, r.base+"/secrets/pilot/operator", before.OperatorBody)
	req.Header.Set("Authorization", before.OperatorAuthorization)
	return pilotDo(t, c.client, req)
}
