//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const pilotSandbox = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefabcd"

var pilotDigest = "sha256:" + strings.Repeat("22", 32)

// The CDS processes, armTLS callbacks, inventory token socket, certificate
// issuance and workload secret requests are real. Hardware evidence, sandbox
// discovery and object storage are fixtures; no container runtime is required.
func TestWorkloadBackendParity(t *testing.T) {
	for _, backend := range []string{"raft", "object-wal", "transactional-metadata"} {
		t.Run(backend, func(t *testing.T) {
			listener, host := inventoryListener(t)
			var objects *objectFixture
			if backend != "raft" {
				objects = newObjectFixture(t)
				if backend == "transactional-metadata" {
					attachMetadata(t, objects)
				}
			}
			nodes := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + seededNodeImage.mrtd + `"}]}`
			c := newClusterWithNodes(t, threeReplicas, objects, nodes, []string{host + "/32"})
			if objects == nil {
				c.waitRollSafe(time.Minute)
			}
			w := startPilotWorkload(c, listener, host)
			ca := c.servedCA(c.replicas[0])
			c.replaceAllowlist(c.replicas[0], "pilot-warmup") // wait out the operator-token floor
			w.setPolicy(true)

			value := []byte("synthetic local pilot secret")
			body := jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(value)})
			authorization, err := c.signer.Authorization(http.MethodPut, "/secrets/pilot/operator", body)
			if err != nil {
				t.Fatal(err)
			}
			put := func(r *replica) (int, []byte) {
				req := pilotRequest(t, http.MethodPut, r.base+"/secrets/pilot/operator", body)
				req.Header.Set("Authorization", authorization)
				return pilotDo(t, c.client, req)
			}
			if code, _ := put(c.replicas[0]); code != http.StatusCreated {
				t.Fatalf("operator create: HTTP %d", code)
			}
			if code, response := put(c.replicas[2]); code != http.StatusConflict || strings.TrimSpace(string(response)) != operatorauth.ErrTokenReused.Error() {
				t.Fatalf("operator token replay on another replica: HTTP %d %s", code, response)
			}

			// A challenge minted by replica 0 is redeemed for a certificate at 1;
			// replica 2 must already know the sandbox binding to release a secret.
			w.issue(c.replicas[0], c.replicas[1])
			w.assertEveryReplicaReads("/pilot/operator", value)
			generated := w.raceCreate()
			w.assertEveryReplicaReads("/pilot/generated", generated)
			t.Log("cross-replica issuance/release, operator replay rejection and concurrent create passed")

			lost := c.replicas[0]
			var originalWriter objectwal.Owner
			if objects != nil {
				code, body := c.get(lost, "/ha/object-wal/status")
				var stats objectwal.Stats
				if code != http.StatusOK || json.Unmarshal(body, &stats) != nil {
					t.Fatal("writer status unavailable")
				}
				originalWriter = stats.Writer
				if originalWriter.ID != c.awaitStatus(lost).ID {
					t.Fatal("healthy preferred writer unexpectedly changed")
				}
			}
			if objects == nil {
				c.waitRollSafe(time.Minute)
				lost = c.waitLeader(30 * time.Second)
			}
			c.kill(lost)
			if objects == nil {
				c.waitLeader(30 * time.Second)
			}
			c.waitFor("the two surviving replicas to serve", 30*time.Second, func() bool { return len(c.serving()) == 2 })
			survivors := c.others(lost)
			w.assertReads(survivors[0], "/pilot/operator", value)
			w.issue(survivors[0], survivors[1])
			if objects != nil {
				code, body := c.get(survivors[1], "/ha/object-wal/status")
				var stats objectwal.Stats
				if code != http.StatusOK || json.Unmarshal(body, &stats) != nil || stats.Writer.ID == originalWriter.ID || stats.Writer.Epoch <= originalWriter.Epoch {
					t.Fatal("issuance did not establish a fenced replacement writer")
				}
			}
			c.restart(lost)
			if objects != nil {
				c.provisionObjects(lost)
			}
			c.waitServing(time.Minute)
			w.assertEveryReplicaReads("/pilot/generated", generated)
			t.Log("issuance and release survived one CDS process loss and replacement")

			if objects != nil {
				for _, r := range c.replicas {
					c.kill(r)
				}
				for _, r := range c.replicas {
					c.restart(r)
					c.provisionObjects(r)
				}
				c.waitServing(time.Minute)
				// Reuse the pre-restart workload certificate over new TLS sessions.
				w.client.CloseIdleConnections()
				for _, r := range c.replicas {
					if c.servedCA(r) != ca {
						t.Fatal("full restart replaced the mesh CA")
					}
				}
				w.assertEveryReplicaReads("/pilot/operator", value)
				w.assertEveryReplicaReads("/pilot/generated", generated)
				if code, response := put(c.replicas[1]); code != http.StatusConflict || strings.TrimSpace(string(response)) != operatorauth.ErrTokenReused.Error() {
					t.Fatalf("spent operator token not remembered after restart: HTTP %d %s", code, response)
				}
				w.issue(c.replicas[2], c.replicas[0])
				t.Log("full process restart preserved CA, policy, secrets and sandbox binding; old leaf still works")

				// Prepare valid requests before the outage to prove the fresh-read
				// gate withholds both issuance and release despite cached state.
				attest := w.attestRequest(c.replicas[0], c.replicas[1])
				read := w.secretRequest(c.replicas[2], http.MethodGet, "/pilot/operator")
				objects.setAuthorityOutage(true)
				for _, check := range []struct {
					client *http.Client
					req    *http.Request
				}{{c.client, attest}, {w.client, read}} {
					if code, _ := pilotDo(t, check.client, check.req); code != http.StatusServiceUnavailable {
						t.Fatalf("%s during storage outage: HTTP %d", check.req.URL.Path, code)
					}
				}
				objects.setAuthorityOutage(false)
				c.waitServing(30 * time.Second)
				w.assertEveryReplicaReads("/pilot/operator", value)
				w.issue(c.replicas[0], c.replicas[2])
				t.Log("storage outage refused valid issuance/release requests; both recovered")
			}

			w.setPolicy(false)
			revokedAt := time.Now()
			staleReads := 0
			for _, r := range c.replicas {
				for {
					req := w.secretRequest(r, http.MethodGet, "/pilot/operator")
					started := time.Now()
					code, _ := pilotDo(t, w.client, req)
					if code == http.StatusForbidden {
						break
					}
					// Current Raft reads under a cached confirmation. Object WAL
					// promises a fresh read per request, in either build mode.
					if objects != nil || code != http.StatusOK || started.Sub(revokedAt) >= processReadLease() {
						t.Fatalf("revocation exceeded %s freshness contract at replica %d after %s: HTTP %d", backend, r.index, started.Sub(revokedAt), code)
					}
					staleReads++
					time.Sleep(50 * time.Millisecond)
				}
			}
			t.Logf("all replicas revoked the existing leaf's grant after %s; %d reads used the previous grant within the %s Raft lease", time.Since(revokedAt), staleReads, processReadLease())
		})
	}
}

// Use one real local IPv4 address and pin exactly its /32 in the launch file.
// CDS's privileged-port and non-loopback inventory checks stay enabled.
func inventoryListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var failures []string
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.To4() == nil || !ip.IsGlobalUnicast() {
			continue
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(workloadclaims.DigestsPort)))
		if err == nil {
			t.Cleanup(func() { listener.Close() })
			return listener, ip.String()
		}
		failures = append(failures, err.Error())
	}
	t.Fatalf("workload integration needs a local non-loopback IPv4 address and permission to bind port %d: %v", workloadclaims.DigestsPort, failures)
	return nil, ""
}

type pilotInventory struct{}

func (pilotInventory) SandboxForPeer(workloadclaims.Peer) (workloadclaims.CallerSandbox, error) {
	return workloadclaims.CallerSandbox{SandboxID: pilotSandbox}, nil
}

func (pilotInventory) DigestsForSandbox(id string) ([]string, []workloadclaims.SandboxContainer, bool, error) {
	if id != pilotSandbox {
		return nil, nil, false, nil
	}
	return []string{pilotDigest}, []workloadclaims.SandboxContainer{{
		Digest: pilotDigest, Argv: []string{"/pilot"}, Mounts: []allowlist.ObservedMount{},
	}}, true, nil
}

type pilotWorkload struct {
	c      *cluster
	apiURL string
	socket string
	key    *ecdsa.PrivateKey
	csr    string
	client *http.Client
}

func startPilotWorkload(c *cluster, listener net.Listener, host string) *pilotWorkload {
	t := c.t
	t.Helper()
	w := &pilotWorkload{c: c, apiURL: c.attestationAPI("workload-node", seededNodeImage.mrtd), key: newKey(t)}
	pins, err := refvalues.ParseRendered([]byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config))))
	if err != nil {
		t.Fatal(err)
	}
	attest := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), w.apiURL)
	tlsConfig, manager, err := workloadclaims.DigestsServerTLSConfig("sev-snp", attest, w.apiURL, armtls.FixedPins(pins), time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.WarmUp(t.Context()); err != nil {
		t.Fatal(err)
	}
	signer, err := workloadclaims.NewSandboxTokenSigner(host)
	if err != nil {
		t.Fatal(err)
	}
	w.socket = "unix://" + filepath.Join(t.TempDir(), "inventory.sock")
	tokens, err := net.Listen("unix", strings.TrimPrefix(w.socket, "unix://"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	digests := tls.NewListener(listener, tlsConfig)
	t.Cleanup(func() { cancel(); tokens.Close(); digests.Close() })
	go func() { _ = workloadclaims.ServeDigests(ctx, digests, pilotInventory{}, signer.PublicKeyDER()) }()
	go func() { _ = workloadclaims.ServeTokens(ctx, tokens, pilotInventory{}, signer) }()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, w.key)
	if err != nil {
		t.Fatal(err)
	}
	w.csr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	return w
}

func (w *pilotWorkload) setPolicy(grant bool) {
	t := w.c.t
	t.Helper()
	secrets := ""
	if grant {
		secrets = `,"secrets":{"policy":"allow","read":["/pilot/**"],"write":["/pilot/generated"]}`
	}
	body := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"pilot-workload":{"containers":[{"digest":"` + pilotDigest +
		`","command":{"policy":"exact","argv":["/pilot"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"}}]` + secrets + `}}}`)
	if code, response := w.c.put(w.c.replicas[0], "/allowlist", body); code != http.StatusNoContent {
		t.Fatalf("set workload grant=%v: HTTP %d %s", grant, code, response)
	}
}

func (w *pilotWorkload) token(challenge string) json.RawMessage {
	t := w.c.t
	t.Helper()
	nonce, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatal(err)
	}
	token, err := workloadclaims.FetchSandboxToken(t.Context(), w.socket, 5*time.Second, &w.key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return jsonBody(t, token)
}

func (w *pilotWorkload) attestRequest(challenger, issuer *replica) *http.Request {
	t := w.c.t
	t.Helper()
	flow := attestclient.NewClientWithHTTP(challenger.base, w.c.client)
	challenge, err := flow.AuthenticateContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	reportData, err := armtls.ReportDataForKey(&w.key.PublicKey, nonce)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := flow.GenerateEvidenceContext(t.Context(), w.apiURL, reportData[:sha512.Size384])
	if err != nil {
		t.Fatal(err)
	}
	body := jsonBody(t, types.AttestRequestBody{Challenge: challenge.Challenge, CSR: w.csr, Evidence: evidence.Envelope(), SandboxToken: w.token(challenge.Challenge)})
	return pilotRequest(t, http.MethodPost, issuer.base+"/attest", body)
}

func (w *pilotWorkload) issue(challenger, issuer *replica) {
	t := w.c.t
	t.Helper()
	code, chain := pilotDo(t, w.c.client, w.attestRequest(challenger, issuer))
	if code != http.StatusOK {
		t.Fatalf("workload issuance: HTTP %d %s", code, chain)
	}
	key, err := x509.MarshalECPrivateKey(w.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}))
	if err != nil {
		t.Fatal(err)
	}
	code, ca := w.c.get(challenger, "/ca")
	roots := x509.NewCertPool()
	if code != http.StatusOK || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("cannot read the authenticated mesh CA")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued certificate does not chain to mesh CA: %v", err)
	}
	if sandbox, err := armtls.SandboxIDFromCert(cert.Leaf); err != nil || sandbox != pilotSandbox {
		t.Fatalf("issued sandbox identity: %q %v", sandbox, err)
	}
	if stamp, err := armtls.MatchedWorkloadFromCert(cert.Leaf); err != nil || stamp == nil || stamp.Name != "pilot-workload" {
		t.Fatalf("issued workload identity: %+v %v", stamp, err)
	}
	if w.client != nil {
		w.client.CloseIdleConnections()
	}
	transport := w.c.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	w.client = &http.Client{Transport: transport, Timeout: 15 * time.Second}
	t.Cleanup(w.client.CloseIdleConnections)
}

func (w *pilotWorkload) secretRequest(r *replica, method, path string) *http.Request {
	t := w.c.t
	t.Helper()
	code, body := w.c.send(r, http.MethodPost, secrets.ChallengeRoute, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("secret challenge: HTTP %d %s", code, body)
	}
	var challenge types.ChallengeResponse
	if err := json.Unmarshal(body, &challenge); err != nil {
		t.Fatal(err)
	}
	req := pilotRequest(t, method, r.base+"/secrets"+path, nil)
	req.Header.Set(secrets.ChallengeHeader, challenge.Challenge)
	req.Header.Set("Authorization", secrets.AuthScheme+base64.StdEncoding.EncodeToString(w.token(challenge.Challenge)))
	return req
}

func (w *pilotWorkload) assertReads(r *replica, path string, want []byte) {
	t := w.c.t
	t.Helper()
	code, body := pilotDo(t, w.client, w.secretRequest(r, http.MethodGet, path))
	if code != http.StatusOK || !bytes.Equal(secretValue(t, body), want) {
		t.Fatalf("replica %d did not release the expected value at %s: HTTP %d", r.index, path, code)
	}
}

func (w *pilotWorkload) assertEveryReplicaReads(path string, want []byte) {
	w.c.t.Helper()
	for _, r := range w.c.replicas {
		w.assertReads(r, path, want)
	}
}

func (w *pilotWorkload) raceCreate() []byte {
	t := w.c.t
	t.Helper()
	requests := make([]*http.Request, 0, len(w.c.replicas))
	for _, r := range w.c.replicas {
		requests = append(requests, w.secretRequest(r, http.MethodPost, "/pilot/generated"))
	}
	type result struct {
		code int
		body []byte
		err  error
	}
	results := make(chan result, len(requests))
	start := make(chan struct{})
	for _, req := range requests {
		go func() {
			<-start
			code, body, err := pilotRoundTrip(w.client, req)
			results <- result{code, body, err}
		}()
	}
	close(start)
	var value []byte
	created, conflicts := 0, 0
	for range requests {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch r.code {
		case http.StatusCreated:
			created++
			value = secretValue(t, r.body)
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("concurrent secret create: HTTP %d %s", r.code, r.body)
		}
	}
	if created != 1 || conflicts != len(requests)-1 || len(value) == 0 {
		t.Fatalf("concurrent create: %d winners, %d conflicts", created, conflicts)
	}
	return value
}

func secretValue(t *testing.T, body []byte) []byte {
	t.Helper()
	var value struct {
		Value []byte `json:"value"`
	}
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value.Value
}

func jsonBody(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func pilotRequest(t *testing.T, method, url string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func pilotDo(t *testing.T, client *http.Client, req *http.Request) (int, []byte) {
	t.Helper()
	code, body, err := pilotRoundTrip(client, req)
	if err != nil {
		t.Fatal(err)
	}
	return code, body
}

func pilotRoundTrip(client *http.Client, req *http.Request) (int, []byte, error) {
	response, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer+1))
	if len(body) > maxAnswer {
		return response.StatusCode, nil, fmt.Errorf("oversized response to %s", req.URL.Path)
	}
	return response.StatusCode, body, err
}
