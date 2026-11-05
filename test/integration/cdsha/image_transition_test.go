//go:build integration && linux

package cdsha_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Real CDS processes, signed decrees, fresh recipient grants and encrypted
// history; attestation, custody roots and storage services remain local fixtures.
// Retiring an image denies NEW grants. It cannot recall keys already issued.
func TestStorageImageTransitionAndInterruptedRecovery(t *testing.T) {
	for _, backend := range []string{"object-wal-current", "transactional-metadata-current", "transactional-current-state"} {
		t.Run(backend, func(t *testing.T) {
			listener, host := inventoryListener(t)
			objects := newObjectFixture(t)
			if strings.HasPrefix(backend, "transactional-") {
				attachMetadata(t, objects)
			}
			if backend == "transactional-current-state" {
				objects.config.DirectState, objects.config.AtomicOperatorWrites = true, true
			}
			protectCurrentRecovery(t, objects)
			c := newClusterWithNodes(t, threeReplicas, objects, nodeImagesCertifying(seededNodeImage), []string{host + "/32"})
			f := objects.recovery
			c.client = c.attestedClient(testutil.TestMeasurement, nextCDSImage)
			w := startPilotWorkload(c, listener, host, testutil.TestMeasurement, nextCDSImage)
			// Populate the old peer-client cache before changing the CDS pins.
			c.replaceAllowlist(c.replicas[1], "upgrade-forward-warmup")
			c.replaceAllowlist(c.replicas[2], "upgrade-forward-warmup")
			w.setPolicy(true)
			ca := c.servedCA(c.replicas[0])
			value := []byte("secret retained across interrupted image upgrade")
			body := jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(value)})
			minted := time.Now()
			authorization, err := c.signer.WithTTL(operatorauth.MaxTokenValidity).Authorization(http.MethodPut, "/secrets/pilot/operator", body)
			if err != nil {
				t.Fatal(err)
			}
			put := func(r *replica) (int, []byte) {
				req := pilotRequest(t, http.MethodPut, r.base+"/secrets/pilot/operator", body)
				req.Header.Set("Authorization", authorization)
				return pilotDo(t, c.client, req)
			}
			if code, answer := put(c.replicas[0]); code != http.StatusCreated {
				t.Fatalf("seed secret: HTTP %d %s", code, answer)
			}
			w.issue(c.replicas[0], c.replicas[1])
			w.assertEveryReplicaReads("/pilot/operator", value)
			refuseFreshRecipient := func(r *replica) {
				t.Helper()
				status := c.awaitStatus(r) // Prove reachability independently of refusal.
				if status.Joined || status.Serving.OK {
					t.Fatal("fresh unprovisioned recipient unexpectedly holds the cluster")
				}
				if _, err := f.authority.Release(t.Context(), r.base); err == nil {
					t.Fatal("current policy released a key to an unapproved image")
				}
			}
			// An image is not approved merely because its process can boot.
			c.rollImage(c.replicas[2], nextCDSImage)
			refuseFreshRecipient(c.replicas[2])
			c.rollImage(c.replicas[2], testutil.TestMeasurement)
			c.provisionObjects(c.replicas[2])
			c.waitServing(30 * time.Second)

			before := c.awaitStatus(c.replicas[0])
			intent, delivered := c.decreePins(c.replicas[0], before.Version, testutil.TestMeasurement, nextCDSImage)
			if delivered.Refused != "" || delivered.Version != before.Version+1 {
				t.Fatalf("overlap image policy: %+v", delivered)
			}
			c.waitFor("overlap image policy on every replica", 30*time.Second, func() bool {
				return c.allApplied(intent, delivered.Version)
			})
			c.rollImage(c.replicas[0], nextCDSImage)
			c.provisionObjects(c.replicas[0])
			c.waitServing(30 * time.Second)
			w.setPolicy(true) // Establish the replacement as preferred writer.
			c.replaceAllowlist(c.replicas[1], "forward-to-approved-new-image")
			if !objects.config.DirectState {
				newWriter := c.awaitStatus(c.replicas[0]).ID
				code, data := c.get(c.replicas[1], "/ha/object-wal/status")
				var stats objectwal.Stats
				if code != http.StatusOK || json.Unmarshal(data, &stats) != nil || stats.Writer.ID != newWriter || stats.Forwarded == 0 {
					t.Fatalf("pin refresh did not forward to the healthy new-image writer: HTTP %d %+v", code, stats)
				}
			}
			w.setPolicy(false)

			assertRecovered := func() {
				t.Helper()
				c.waitServing(30 * time.Second)
				w.client.CloseIdleConnections()
				// A timeout or expired token cannot masquerade as replay rejection.
				if time.Since(minted) >= operatorauth.MaxTokenValidity-3*time.Second {
					t.Fatal("test exceeded the spent token's validity window")
				}
				for _, r := range c.replicas {
					if c.servedCA(r) != ca {
						t.Fatal("image transition changed the CA")
					}
					if code, answer := put(r); code != http.StatusConflict || strings.TrimSpace(string(answer)) != operatorauth.ErrTokenReused.Error() {
						t.Fatalf("image transition forgot a spent token: HTTP %d %s", code, answer)
					}
					if code, _ := pilotDo(t, w.client, w.secretRequest(r, http.MethodGet, "/pilot/operator")); code != http.StatusForbidden {
						t.Fatalf("image transition forgot acknowledged revocation: HTTP %d", code)
					}
				}
				w.setPolicy(true)
				w.assertEveryReplicaReads("/pilot/operator", value) // Original leaf and secret.
				w.setPolicy(false)
			}
			coldRestart := func(r *replica) {
				t.Helper()
				r.db = filepath.Join(t.TempDir(), "empty-allowlist.db")
				c.restart(r)
			}
			// Interrupt while one new and two old images are still approved.
			for _, r := range c.replicas {
				c.kill(r)
			}
			f.restore(c) // The ORIGINAL capsule and enrollment, with an empty replay FSM.
			for _, r := range c.replicas {
				coldRestart(r)
				c.provisionObjects(r)
			}
			assertRecovered()
			t.Log("mixed-image full process loss preserved CA, replay protection, revocation and original leaf/secret")

			before = c.awaitStatus(c.replicas[0])
			_, delivered = c.decreePins(c.replicas[0], before.Version, nextCDSImage)
			if delivered.Refused != "" || delivered.Version != before.Version+1 {
				t.Fatalf("retirement: %+v", delivered)
			}
			stale := f.last[c.replicas[2].index]
			for _, r := range c.replicas {
				c.kill(r)
			}
			f.restore(c)
			coldRestart(c.replicas[2]) // Old image is reachable but now retired.
			refuseFreshRecipient(c.replicas[2])
			if code, _ := c.send(c.replicas[2], http.MethodPost, "/ha/object-wal/provision", stale, nil); code != http.StatusForbidden {
				t.Fatalf("retired replacement accepted a previous incarnation's grant: HTTP %d", code)
			}
			coldRestart(c.replicas[0])
			c.provisionObjects(c.replicas[0])
			for _, r := range c.replicas[1:] {
				c.rollImage(r, nextCDSImage)
				c.provisionObjects(r)
			}
			assertRecovered()
			t.Log("cold authority refused new grants to the retired image; approved replacements recovered the same identity and state")
		})
	}
}
