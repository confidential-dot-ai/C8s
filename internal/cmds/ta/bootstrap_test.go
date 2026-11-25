package ta

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/secrets"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taconfig"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/certutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/types"
)

// Mocked attestation verdicts exercise runtime wiring and launch binding, not
// hardware verification. Workload secret release still needs a real inventory.
func TestRunFreshChainBootstrap(t *testing.T) {
	const workerLaunch = "schemaVersion: c8s-worker/v1\nclusterID: lane\n"
	cfg := armTLSRunConfig(t)
	operator, keysPEM := operatorKeyPair(t)
	endpoint := fmt.Sprintf("127.0.0.1:%d", cfg.port)
	document := measuredDocument(t, cluster{
		operatorPEM: keysPEM,
		workloads: map[string]string{
			"cds": digestA,
		},
		nodes: `{"schema_version":"1","tee":"sev-snp","measurements":[]}`,
	})
	document = append(document, []byte("\nha:\n  endpoints: ["+endpoint+"]\n")...)
	var err error
	cfg.measured, err = taconfig.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ha = haConfig{
		storeMemory:  true,
		gossip:       50 * time.Millisecond,
		peerTimeout:  50 * time.Millisecond,
		storeTimeout: time.Second,
	}
	// Only the spent-token database persists; the fresh HA chain stays in memory.
	cfg.allowlistPersistent = true
	stub := newStubAttestationApi(t, testLaunchDigest)
	cfg.attestationApiURL = stub.URL()
	verdict := mockapi.PassingVerdict(testLaunchDigest)
	launchedWith := func(file []byte) {
		binding := runtimemeasure.HostData(file)
		verdict.Claims.InitData = binding[:]
		stub.SetVerdict(verdict)
	}
	launchedWith(document)
	base, client := startRunServer(t, cfg)
	t.Cleanup(client.CloseIdleConnections)

	encode := func(value any) []byte {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	request := func(method, path string, body []byte, auth string, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", auth)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d (%s), want %d", method, path, resp.StatusCode, got, want)
		}
		return got
	}
	measurements, err := refvalues.ParseRendered(fetch(t, client, base+"/measurements"))
	if err != nil || measurements.Family != teetypes.FamilySNP || len(measurements.Images) != 0 {
		t.Fatalf("fresh measurements = %+v, %v", measurements, err)
	}
	request(http.MethodPost, "/authenticate", nil, "", http.StatusServiceUnavailable)
	var pending taha.Pending
	fetchJSON(t, client, base+taha.GenesisPath, &pending)
	genesis, err := cdschain.Sign(operator, cdschain.Body{
		Cluster: "lane",
		Type:    cdschain.TypeGenesis,
		Payload: encode(cdschain.Genesis{
			Endpoints:    []string{endpoint},
			Members:      []string{pending.Member},
			OperatorKeys: string(keysPEM),
			CAKey:        pending.CAKey,
			Accepted: []cdschain.Build{{
				Measurements: testutil.TAPinDocument(testLaunchDigest, string(document)),
				Version:      "v1.0.0",
			}},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request(http.MethodPost, taha.GenesisPath, encode(genesis), "", http.StatusNoContent)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var status taha.Status
		fetchJSON(t, client, base+taha.StatusPath, &status)
		if status.Build == "v1.0.0" && status.Serving == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("genesis never became serving: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	launchedWith([]byte(workerLaunch))

	csr, _ := generateCSR(t)
	issue := func(want int) []byte {
		t.Helper()
		var challenge types.ChallengeResponse
		if err := json.Unmarshal(request(http.MethodPost, "/authenticate", nil, "", http.StatusOK), &challenge); err != nil {
			t.Fatal(err)
		}
		response := request(http.MethodPost, "/attest", encode(types.AttestRequestBody{
			Challenge: challenge.Challenge,
			CSR:       csr,
			Evidence: teetypes.AttestationEvidence{
				Platform: teetypes.PlatformSNP,
				Evidence: json.RawMessage(`{"test":true}`),
			},
		}), "", want)
		if want == http.StatusForbidden && errorCode(t, response) != types.ErrorCodeMeasurementDenied {
			t.Fatalf("issuance refused for a different reason: %s", response)
		}
		return response
	}
	issue(http.StatusForbidden)
	// Secret routes must already be mounted, but a caller without a verified
	// sandbox leaf and a fresh inventory token cannot read a stored value.
	denyRelease := func() {
		t.Helper()
		var challenge types.ChallengeResponse
		if err := json.Unmarshal(request(http.MethodPost, secrets.ChallengeRoute, nil, "", http.StatusOK), &challenge); err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/secrets/bootstrap", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(secrets.ChallengeHeader, challenge.Challenge)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("unauthenticated secret release = %d, want 403", resp.StatusCode)
		}
	}
	denyRelease()

	nodes, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:       "worker",
			Digest:     mustDecode(t, testLaunchDigest),
			LaunchFile: []byte(workerLaunch),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := cdschain.Sign(operator, cdschain.Body{
		Cluster: "lane",
		Seq:     1,
		Prev:    genesis.Hash(),
		Type:    cdschain.TypeNodes,
		Payload: encode(cdschain.Nodes{Nodes: string(nodes)}),
	})
	if err != nil {
		t.Fatal(err)
	}
	request(http.MethodPost, taha.EntriesPath, encode(entry), "", http.StatusOK)
	measurements, err = refvalues.ParseRendered(fetch(t, client, base+"/measurements"))
	if err != nil || len(measurements.Images) != 1 || !bytes.Equal(measurements.Images[0].LaunchFile, []byte(workerLaunch)) {
		t.Fatalf("admitted measurements = %+v, %v", measurements, err)
	}
	issued := issue(http.StatusOK)
	if _, err := certutil.ParseCertificatePEM(issued); err != nil {
		t.Fatalf("issuance returned no certificate: %v: %s", err, issued)
	}
	launchedWith([]byte(workerLaunch + "changed: true\n"))
	issue(http.StatusForbidden)

	signer, err := operatorauth.NewSigner(operator)
	if err != nil {
		t.Fatal(err)
	}
	put := encode(secrets.PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("synthetic-bootstrap-value"))})
	auth := sign(t, signer, http.MethodPut, "/secrets/bootstrap", put)
	request(http.MethodPut, "/secrets/bootstrap", put, "", http.StatusUnauthorized)
	request(http.MethodPut, "/secrets/bootstrap", put, auth, http.StatusCreated)
	request(http.MethodPut, "/secrets/bootstrap", put, auth, http.StatusConflict)
	denyRelease()
}
