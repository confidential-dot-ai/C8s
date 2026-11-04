//go:build integration && linux

package cdsha_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// All arms must stop authorizing a leaf of the old CA after a rotation is
// acknowledged, including on a TLS connection established before the change.
// The durable arms must then recover the new key and acknowledged state after
// losing every CDS process. Hardware evidence and inventory are fixtures.
func TestCARotationBackendParity(t *testing.T) {
	for _, backend := range []string{"raft", "object-wal", "transactional-metadata", "object-wal-protected", "transactional-metadata-protected", "object-wal-current", "transactional-metadata-current"} {
		t.Run(backend, func(t *testing.T) {
			listener, host := inventoryListener(t)
			var objects *objectFixture
			if backend != "raft" {
				objects = newObjectFixture(t)
				if strings.HasPrefix(backend, "transactional-metadata") {
					attachMetadata(t, objects)
				}
				if strings.HasSuffix(backend, "-protected") {
					protectRecovery(t, objects)
				}
				if strings.HasSuffix(backend, "-current") {
					protectCurrentRecovery(t, objects)
				}
			}
			c := newClusterWithNodes(t, threeReplicas, objects, nodeImagesCertifying(seededNodeImage), []string{host + "/32"})
			if objects == nil {
				c.waitRollSafe(time.Minute)
			}
			w := startPilotWorkload(c, listener, host)
			c.replaceAllowlist(c.replicas[0], "rotation-warmup")
			w.setPolicy(true)
			value := []byte("synthetic secret retained across CA rotation")
			body := jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(value)})
			authorization, err := c.signer.WithTTL(operatorauth.MaxTokenValidity).Authorization(http.MethodPut, "/secrets/pilot/operator", body)
			if err != nil {
				t.Fatal(err)
			}
			put := func(r *replica) (int, []byte) {
				req := pilotRequest(t, http.MethodPut, r.base+"/secrets/pilot/operator", body)
				req.Header.Set("Authorization", authorization)
				return pilotDo(t, c.client, req)
			}
			if code, response := put(c.replicas[0]); code != http.StatusCreated {
				t.Fatalf("pre-rotation secret: HTTP %d %s", code, response)
			}
			w.issue(c.replicas[0], c.replicas[1])
			w.assertEveryReplicaReads("/pilot/operator", value)
			before := c.awaitStatus(c.replicas[0])
			intent, delivered := c.decreeRotateKey(c.replicas[1], before.Version)
			if delivered.Refused != "" || delivered.Held || delivered.Version != before.Version+1 {
				t.Fatalf("rotation was not acknowledged: %+v", delivered)
			}
			// Raft can drop its serving lease while following the new key.
			// A 503 is an availability gap, not stale authorization. Leave
			// the workload's existing TLS connections open while it recovers.
			c.waitServing(30 * time.Second)

			for _, r := range c.replicas {
				// Mint a new challenge after rotation, so a refusal must not
				// be explained by an obsolete challenge MAC.
				req := w.secretRequest(r, http.MethodGet, "/pilot/operator")
				var reused atomic.Bool
				trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
				code, _, err := pilotRoundTrip(w.client, req)
				if err != nil || code != http.StatusForbidden || !reused.Load() {
					t.Fatalf("old CA on an existing TLS connection after acknowledged rotation, replica %d: HTTP %d reused=%t error=%v",
						r.index, code, reused.Load(), err)
				}
			}
			c.waitFor("all replicas to apply one rotation", 30*time.Second, func() bool {
				return c.allApplied(intent, before.Version+1) && c.allServeOneOtherCA(before.CAFingerprint)
			})
			rotated := c.servedCA(c.replicas[0])
			if code, response := put(c.replicas[2]); code != http.StatusConflict || strings.TrimSpace(string(response)) != operatorauth.ErrTokenReused.Error() {
				t.Fatalf("rotation forgot a spent operator token: HTTP %d %s", code, response)
			}
			w.issue(c.replicas[2], c.replicas[0])
			// Root publication to the TLS listener is asynchronous. Wait for
			// new handshakes, without relaxing immediate old-leaf refusal.
			for _, r := range c.replicas {
				c.waitFor("new CA client handshake", 10*time.Second, func() bool {
					req := pilotRequest(t, http.MethodGet, r.base+"/allowlist", nil)
					code, _, err := pilotRoundTrip(w.client, req)
					return err == nil && code == http.StatusOK
				})
			}
			w.assertEveryReplicaReads("/pilot/operator", value)
			t.Log("rotation rejected old leaves on existing TLS connections; newly issued leaves read the preserved secret")

			if objects != nil {
				w.setPolicy(false) // The revocation must survive losing every CDS process.
				for _, r := range c.replicas {
					c.kill(r)
				}
				if objects.recovery != nil {
					objects.recovery.restore(c)
				}
				for _, r := range c.replicas {
					c.restart(r)
					c.provisionObjects(r)
				}
				c.waitServing(time.Minute)
				w.client.CloseIdleConnections()
				for _, r := range c.replicas {
					if c.servedCA(r) != rotated {
						t.Fatal("cold recovery replaced the rotated CA")
					}
					if code, _ := pilotDo(t, w.client, w.secretRequest(r, http.MethodGet, "/pilot/operator")); code != http.StatusForbidden {
						t.Fatalf("cold recovery forgot acknowledged revocation on replica %d: HTTP %d", r.index, code)
					}
				}
				w.setPolicy(true)
				w.assertEveryReplicaReads("/pilot/operator", value)
				if code, response := put(c.replicas[1]); code != http.StatusConflict || strings.TrimSpace(string(response)) != operatorauth.ErrTokenReused.Error() {
					t.Fatalf("cold recovery forgot a spent operator token: HTTP %d %s", code, response)
				}
				t.Log("total CDS process loss retained the rotated CA, existing leaf, secret, binding, spent token and acknowledged revocation")
			}
			w.setPolicy(false)
			for _, r := range c.replicas {
				if code, _ := pilotDo(t, w.client, w.secretRequest(r, http.MethodGet, "/pilot/operator")); code != http.StatusForbidden {
					t.Fatalf("post-rotation revocation released a secret on replica %d: HTTP %d", r.index, code)
				}
			}
		})
	}
}
