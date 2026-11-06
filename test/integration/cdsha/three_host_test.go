//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-three-host/protocol"
	"golang.org/x/net/netutil"
)

var threeHostConfig *cdsconfig.Config
var threeHostLaunch []byte

func threeHostMain(m *testing.M) {
	if len(os.Args) != 3 || os.Args[1] != "-test.run=^TestThreeHostAgent$" || os.Args[2] != "-test.v" {
		panic("fixed three-host invocation required")
	}
	var err error
	threeHostLaunch, err = os.ReadFile("/run/confai/operator-pubkey")
	if err != nil {
		panic(err)
	}
	threeHostConfig, err = cdsconfig.Parse(threeHostLaunch)
	if err != nil {
		panic(err)
	}
	if threeHostConfig.HA == nil || len(threeHostConfig.HA.Replicas) != 3 || threeHostConfig.Nodes.Family != "tdx" || len(threeHostConfig.Nodes.Images) != 2 {
		panic("three replicas and two complete TDX image tuples required")
	}
	for _, p := range threeHostConfig.Nodes.Images {
		if len(p.Registers[1]) != 48 || len(p.Registers[2]) != 48 {
			panic("incomplete TDX tuple")
		}
	}
	releaseProcesses = true
	os.Exit(m.Run())
}

type threeHostJob struct {
	q             protocol.Request
	authorization string
	reply         chan protocol.Reply
}
type threeHostState struct {
	c          *cluster
	w          *pilotWorkload
	ca         string
	spent      string
	spentAt    time.Time
	prepared   *http.Request
	preparedAt time.Time
}

// One parent test owns the inventory, in-guest leaf key, and bounded command
// mailbox for this cluster. Subtests report failed assertions without exporting
// any workload private key. This is a qualification agent, never a CDS feature.
func TestThreeHostAgent(t *testing.T) {
	if threeHostConfig == nil {
		t.Skip("fixed measured image only")
	}
	jobs := make(chan threeHostJob, 8)
	verify := operatorauth.Verifier{Keys: threeHostConfig.OperatorKeys.Keys()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /phase", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		if err != nil || strictjson.Validate(body) != nil || verify.Authorize(r, body) != nil {
			http.Error(w, "unauthorized phase", 401)
			return
		}
		var q protocol.Request
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if dec.Decode(&q) != nil || !q.Valid() {
			http.Error(w, "invalid fixed phase", 400)
			return
		}
		job := threeHostJob{q, r.Header.Get("Authorization"), make(chan protocol.Reply, 1)}
		select {
		case jobs <- job:
		default:
			http.Error(w, "phase backpressure", 429)
			return
		}
		select {
		case out := <-job.reply:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case <-r.Context().Done():
		}
	})
	attest := attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), "http://127.0.0.1:8400")
	cfg, manager, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{Platform: "tdx", AttestFunc: attest, CertTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Minute)
	defer cancel()
	if err = manager.WarmUp(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:6443")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	t.Cleanup(func() { _ = server.Close() })
	go manager.RunRotation(ctx)
	go func() { _ = server.Serve(tls.NewListener(netutil.LimitListener(listener, 16), cfg)) }()
	var s threeHostState
	seen := make(map[[32]byte]time.Time)
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-jobs:
			start := time.Now()
			out := protocol.Reply{Operation: job.q.Operation, Checks: map[string]any{}}
			hash := sha256.Sum256([]byte(job.authorization))
			for k, expiry := range seen {
				if time.Now().After(expiry) {
					delete(seen, k)
				}
			}
			if _, duplicate := seen[hash]; duplicate || len(seen) >= 512 {
				job.reply <- out
				continue
			}
			_, expiry, err := operatorauth.UnverifiedTimes(strings.TrimPrefix(job.authorization, "Bearer "))
			if err != nil || !time.Now().Before(expiry) {
				job.reply <- out
				continue
			}
			seen[hash] = expiry
			if job.q.Operation == "init" && s.c == nil {
				// Create long-lived inventory under the parent, not a phase subtest.
				s.c = &cluster{t: t, name: threeHostConfig.ClusterID, config: threeHostLaunch, dir: t.TempDir()}
				s.c.operator, err = certutil.ParseECPrivateKey(job.q.OperatorKey)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.ContainsFunc(threeHostConfig.OperatorKeys.Keys(), func(k *ecdsa.PublicKey) bool { return k.Equal(&s.c.operator.PublicKey) }) {
					t.Fatal("operator key differs from measured key set")
				}
				s.c.signer = s.c.operatorSigner()
				s.c.client = s.c.attestedClient(s.c.measurement())
				s.c.client.Timeout = 20 * time.Second
				for i, host := range threeHostConfig.HA.Replicas {
					s.c.replicas = append(s.c.replicas, &replica{index: i, host: host, base: "https://" + host + ":8443"})
				}
				if threeHostConfig.HA.ObjectWALPilot != nil {
					s.c.objectWAL = &objectFixture{config: *threeHostConfig.HA.ObjectWALPilot, provision: bytes.Clone(job.q.Provision)}
				}
				ln, host := inventoryListener(t)
				// Each guest models a different sandbox. A replacement also gets a
				// fresh ID even if DHCP reuses its old address; the inventory signer
				// is a new identity and cannot take over the previous binding.
				var sandbox [32]byte
				if _, err := rand.Read(sandbox[:]); err != nil {
					t.Fatal(err)
				}
				pilotSandbox = hex.EncodeToString(sandbox[:])
				s.w = startPilotWorkload(s.c, ln, host)
			}
			if s.c == nil {
				job.reply <- out
				continue
			}
			out.Passed = t.Run(job.q.Operation, func(st *testing.T) { s.c.t = st; defer func() { s.c.t = t }(); s.phase(job.q, out.Checks) })
			out.Seconds = time.Since(start).Seconds()
			job.reply <- out
		}
	}
}

func (s *threeHostState) phase(q protocol.Request, out map[string]any) {
	c, w, t := s.c, s.w, s.c.t
	c.client.CloseIdleConnections()
	target := c.replicas[q.Target]
	others := c.others(target)
	value := []byte("synthetic three-host qualification secret")
	putBody := jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(value)})
	replay := func(r *replica) {
		if s.spent == "" || time.Since(s.spentAt) > 4*time.Minute {
			t.Fatal("live spent token required")
		}
		req := pilotRequest(t, "PUT", r.base+"/secrets/pilot/operator", putBody)
		req.Header.Set("Authorization", s.spent)
		code, body := pilotDo(t, c.client, req)
		if code != 409 || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
			t.Fatalf("spent token not rejected: %d %s", code, body)
		}
	}
	sameCA := func() {
		for _, r := range c.replicas {
			v := c.servedCA(r)
			if s.ca != "" && v != s.ca {
				t.Fatal("mesh CA changed")
			}
			s.ca = v
		}
		out["ca_fingerprint"] = s.ca
	}
	switch q.Operation {
	case "init":
		out["initialized"] = true
	case "status":
		statuses := make([]any, 0, 3)
		for _, r := range c.replicas {
			v, ok := c.status(r)
			statuses = append(statuses, map[string]any{"answered": ok, "status": v})
		}
		out["replicas"] = statuses
	case "provision":
		if c.objectWAL != nil {
			c.provisionObjects(target)
		}
	case "seed":
		// The initial CDS admission set contains image A. Node/workload inventory
		// pins cover A and B so their rolling replacement is independently trusted.
		initial := c.nativeTDXPins()
		initial.Images = initial.Images[:1]
		pinBytes, err := refvalues.Render(initial)
		if err != nil {
			t.Fatal(err)
		}
		pins, err := cdsdecree.NewPinDocument(pinBytes)
		if err != nil {
			t.Fatal(err)
		}
		nodesBytes, err := refvalues.Render(threeHostConfig.Nodes)
		if err != nil {
			t.Fatal(err)
		}
		nodes, err := cdsdecree.NewNodeImages(nodesBytes)
		if err != nil {
			t.Fatal(err)
		}
		status := c.awaitStatus(target)
		c.decree(target, cdsdecree.Decree{ClusterID: c.id(), IntentID: cdsdecree.NewIntentID(), Kind: cdsdecree.Genesis, ExpiresAt: time.Now().Add(time.Hour), CDSPins: pins, NodePins: nodes, TargetMember: status.ID, TargetAddress: target.host + ":8443", IssuedAtMS: time.Now().UnixMilli(), GenesisCA: status.GenesisCA})
		c.waitServing(2 * time.Minute)
		c.replaceAllowlist(target, "pilot-warmup")
		w.setPolicy(true)
		if code, body := c.put(target, "/secrets/pilot/operator", putBody); code != 201 {
			t.Fatalf("seed secret: %d %s", code, body)
		}
		sameCA()
		w.issue(c.replicas[0], c.replicas[1])
		w.assertEveryReplicaReads("/pilot/operator", value)
	case "attach":
		c.waitServing(2 * time.Minute)
		sameCA()
		w.issue(target, others[0])
	case "burst":
		w.issuanceBurst(value)
		out["issuances"] = 24
		out["releases"] = 24
	case "prepare":
		var err error
		s.spent, err = c.signer.WithTTL(operatorauth.MaxTokenValidity).Authorization("PUT", "/secrets/pilot/operator", putBody)
		if err != nil {
			t.Fatal(err)
		}
		s.spentAt = time.Now()
		req := pilotRequest(t, "PUT", target.base+"/secrets/pilot/operator", putBody)
		req.Header.Set("Authorization", s.spent)
		code, body := pilotDo(t, c.client, req)
		if code != 409 || strings.TrimSpace(string(body)) == operatorauth.ErrTokenReused.Error() {
			t.Fatalf("fresh token not consumed by existing-secret conflict: %d %s", code, body)
		}
		replay(others[0])
		s.prepared = w.secretRequest(target, "GET", "/pilot/operator").Clone(context.Background())
		s.preparedAt = time.Now()
		out["prepared_valid_request"] = true
	case "refuse":
		if s.prepared == nil || time.Since(s.preparedAt) > 40*time.Second {
			t.Fatal("unexpired pre-fault request required")
		}
		code, body := pilotDo(t, w.client, s.prepared.Clone(t.Context()))
		if code != 503 {
			t.Fatalf("isolated authority did not explicitly refuse: %d %s", code, body)
		}
		out["valid_release_refused"] = true
	case "survive":
		c.waitFor("survivors serving", 45*time.Second, func() bool {
			for _, r := range others {
				v, ok := c.status(r)
				if !ok || !v.Serving.OK {
					return false
				}
			}
			return true
		})
		w.issue(others[0], others[1])
		w.assertReads(others[0], "/pilot/operator", value)
		replay(others[1])
		w.setPolicyAt(others[0], false)
		for _, r := range others {
			code, _ := pilotDo(t, w.client, w.secretRequest(r, "GET", "/pilot/operator"))
			if code != 403 {
				t.Fatalf("revocation during failover: replica %d HTTP %d", r.index, code)
			}
		}
		out["revocation_during_failover"] = true
		// Explicitly restore the grant before the separate authority outage.
		w.setPolicyAt(others[0], true)
		w.assertReads(others[1], "/pilot/operator", value)
		out["majority_served"] = true
	case "heal":
		c.waitServing(2 * time.Minute)
		sameCA()
		w.assertEveryReplicaReads("/pilot/operator", value)
		for _, r := range c.replicas {
			replay(r)
		}
	case "revoke":
		w.setPolicy(false)
		out["revocation_acknowledged"] = true
	case "revoked":
		c.waitServing(2 * time.Minute)
		sameCA()
		for _, r := range c.replicas {
			replay(r)
			code, _ := pilotDo(t, w.client, w.secretRequest(r, "GET", "/pilot/operator"))
			if code != 403 {
				t.Fatalf("revoked release on replica %d: %d", r.index, code)
			}
		}
		out["revocation_preserved"] = true
	case "roll-safe":
		c.waitServing(2 * time.Minute)
		if c.objectWAL == nil {
			c.waitEveryReplicaJoined(2 * time.Minute)
			c.waitVoter(target, 2*time.Minute)
			c.waitRollSafe(2 * time.Minute)
		}
		sameCA()
	case "overlap", "retire":
		rv := c.nativeTDXPins()
		if q.Operation == "retire" {
			rv.Images = rv.Images[1:]
		}
		b, err := refvalues.Render(rv)
		if err != nil {
			t.Fatal(err)
		}
		pins, err := cdsdecree.NewPinDocument(b)
		if err != nil {
			t.Fatal(err)
		}
		status := c.awaitStatus(target)
		d := cdsdecree.Decree{ClusterID: c.id(), IntentID: cdsdecree.NewIntentID(), Kind: cdsdecree.UpdateMeasurements, ExpiresAt: time.Now().Add(time.Hour), BaseVersion: status.Version, CDSPins: pins}
		result := c.decree(target, d)
		out["delivered"] = result
	case "admit":
		b, err := refvalues.Render(c.nativeTDXPins())
		if err != nil {
			t.Fatal(err)
		}
		pins, err := cdsdecree.NewPinDocument(b)
		if err != nil {
			t.Fatal(err)
		}
		c.decree(target, cdsdecree.Decree{ClusterID: c.id(), IntentID: cdsdecree.NewIntentID(), Kind: cdsdecree.Admit, ExpiresAt: time.Now().Add(time.Hour), CDSPins: pins, TargetMember: c.awaitStatus(target).ID})
	default:
		t.Fatal("unhandled fixed phase")
	}
}

func threeHostMeasurement() string { return hex.EncodeToString(threeHostConfig.Nodes.Images[0].Digest) }
