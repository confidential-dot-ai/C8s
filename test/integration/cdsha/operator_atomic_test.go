//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func atomicOperatorWritesEnabled() bool { return os.Getenv("CDSHA_ATOMIC_OPERATOR_WRITES") == "1" }

// Exercise the real server routes, verifier, committed stores and response
// encodings in both modes. A refused valid request must still spend its token;
// invalid signatures and impossible If-Match syntax must not spend it.
func TestAtomicOperatorHTTPCompatibility(t *testing.T) {
	type response struct {
		code                     int
		body, contentType, cache string
	}
	baseline := map[string]response{}
	for _, mode := range []string{"legacy", "atomic", "direct-state"} {
		t.Run(mode, func(t *testing.T) {
			enabled := mode != "legacy"
			listener, host := inventoryListener(t)
			t.Cleanup(func() { _ = listener.Close() })
			f := newObjectFixture(t)
			f.config.AtomicOperatorWrites = enabled
			if mode == "direct-state" {
				attachMetadata(t, f)
				f.config.DirectState = true
			}
			c := newClusterWithNodes(t, threeReplicas, f, nodeImagesCertifying(seededNodeImage), []string{host + "/32"})
			c.replaceAllowlist(c.replicas[0], "atomic-compatibility-warmup")
			send := func(path string, body []byte, auth, match string) response {
				req := pilotRequest(t, http.MethodPut, c.replicas[0].base+path, body)
				req.Header.Set("Authorization", auth)
				if match != "" {
					req.Header.Set("If-Match", match)
				}
				resp, err := c.client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
				if err != nil {
					t.Fatal(err)
				}
				return response{resp.StatusCode, string(data), resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control")}
			}
			check := func(name string, r response, want int) {
				if r.code != want {
					t.Fatalf("%s: HTTP %d %s, want %d", name, r.code, r.body, want)
				}
				if enabled {
					if r != baseline[name] {
						t.Errorf("%s changed HTTP contract: atomic=%+v legacy=%+v", name, r, baseline[name])
					}
				} else {
					baseline[name] = r
				}
			}
			manifest := `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":86400,"hosts":{"app.example":{"routes":[{"path":"/","match":"prefix","backend":{"address":"app.example:443","workload":"app"}}]}}}`
			nextManifest := strings.Replace(manifest, `"revision":1`, `"revision":2`, 1)
			code, ca := c.get(c.replicas[0], "/ca")
			if code != http.StatusOK {
				t.Fatal("mesh CA unavailable")
			}
			anchor, err := json.Marshal(string(ca))
			if err != nil {
				t.Fatal(err)
			}
			excludedManifest := strings.Replace(nextManifest, `"workload":"app"`, `"serverName":"app.example","ca":`+string(anchor), 1)
			for _, tc := range []struct {
				name, path, body, match string
				want                    int
			}{
				{"create", "/secrets/pilot/atomic", `{"value":"c2FtZQ=="}`, "", 201},
				{"occupied", "/secrets/pilot/atomic", `{"value":"b3RoZXI="}`, "", 409},
				{"overwrite", "/secrets/pilot/atomic", `{"value":"bmV3","overwrite":true}`, "", 200},
				{"empty", "/secrets/pilot/empty", `{"value":""}`, "", 422},
				{"unknown field", "/secrets/pilot/bad", `{"value":"eA==","extra":1}`, "", 422},
				{"malformed secret", "/secrets/pilot/bad", `{`, "", 422},
				{"escaped path", "/secrets/pilot%2fencoded", `{"value":"eA=="}`, "", 400},
				{"oversized value", "/secrets/pilot/large", `{"value":"` + strings.Repeat("eHh4", 1400) + `"}`, "", 500},
				{"malformed allowlist", "/allowlist", `{`, "", 422},
				{"version conflict", "/allowlist", string(allowlistDocument("atomic-version")), `"0"`, 412},
				{"allowlist", "/allowlist", string(allowlistDocument("atomic-accepted")), "", 204},
				{"malformed routes", "/routes", `{`, "", 422},
				{"routes", "/routes", manifest, "", 204},
				{"route revision conflict", "/routes", manifest, "", 409},
				{"route digest conflict", "/routes", nextManifest, `"wrong-digest"`, 412},
				{"excluded mesh CA", "/routes", excludedManifest, "", 422},
				{"route revision after conflict", "/routes", nextManifest, "", 204},
			} {
				req := pilotRequest(t, http.MethodPut, c.replicas[0].base+tc.path, nil)
				body := []byte(tc.body)
				auth, err := c.signer.Authorization(http.MethodPut, req.URL.Path, body)
				if err != nil {
					t.Fatal(err)
				}
				before := c.comparisonStats().CommittedCommands
				check(tc.name, send(tc.path, body, auth, tc.match), tc.want)
				if enabled && c.comparisonStats().CommittedCommands-before != 1 {
					t.Fatalf("%s did not commit exactly one command", tc.name)
				}
				replayed := send(tc.path, body, auth, tc.match)
				check(tc.name+" replay", replayed, http.StatusConflict)
				if strings.TrimSpace(replayed.body) != operatorauth.ErrTokenReused.Error() {
					t.Fatalf("%s is not a spent-token refusal", tc.name)
				}
			}
			body := []byte(`{"value":"eA=="}`)
			path := "/secrets/pilot/binding"
			auth, err := c.signer.Authorization(http.MethodPut, path, body)
			if err != nil {
				t.Fatal(err)
			}
			check("body binding", send(path, []byte(`{"value":"eQ=="}`), auth, ""), 401)
			check("binding refusal did not spend", send(path, body, auth, ""), 201)
			body = allowlistDocument("syntax-refusal")
			auth, err = c.signer.Authorization(http.MethodPut, "/allowlist", body)
			if err != nil {
				t.Fatal(err)
			}
			check("impossible version", send("/allowlist", body, auth, `W/"1"`), 412)
			check("syntax refusal did not spend", send("/allowlist", body, auth, ""), 204)
			tooBig := bytes.Repeat([]byte("x"), 2<<20)
			before := c.comparisonStats().CommittedCommands
			// The existing outer MaxBytesReader is reported by ReadCappedBody
			// as HTTP 400. Preserve this public contract in the pilot.
			check("body cap", send("/allowlist", tooBig, "Bearer invalid", ""), 400)
			if c.comparisonStats().CommittedCommands != before {
				t.Fatal("oversized request reached the durable log")
			}
		})
	}
}
