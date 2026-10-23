package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

var testAllowlistPin = "sha256:" + hex.EncodeToString(testAllowlistDigest)

// TestTranscriptWithoutAllowlistDigestRejected signs the v1 layout, which
// ends at the route digest, under the current binding id: a client must not
// accept it.
func TestTranscriptWithoutAllowlistDigestRejected(t *testing.T) {
	id := mintEndpointIdentity(t)
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)

	t.Run("attest-pq", func(t *testing.T) {
		sess := fakeSession(0x10)
		var obj map[string]any
		if err := json.Unmarshal(buildEndpointJSON(t, id, nonce, bytes.Repeat([]byte{0x01}, 64), []byte("vcek"), sess), &obj); err != nil {
			t.Fatal(err)
		}
		v1 := transcriptOf([]byte(types.ProtocolVersion), []byte("cds"), sum256(id.ca.Raw), sum256(id.leaf.Raw), sess.ek, sess.ct, sess.sid, nonce, testRouteDigest)
		obj["identity_proof"] = id.proofJSON(t, v1)
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(data, nonce, sess.ek, testRoute, "test"); !isSecurityError(err) {
			t.Fatalf("bundle over the v1 layout: err = %v, want a security error", err)
		}
	})
	t.Run("attest-lb", func(t *testing.T) {
		serving := []byte("serving-der")
		v1 := transcriptOf([]byte(types.BindingAttestLB), []byte("cds"), nonce, sum256(serving), sum256(id.leaf.Raw), sum256(id.ca.Raw), testRouteDigest)
		data, err := json.Marshal(map[string]any{
			"version":          types.BindingAttestLB,
			"platform":         "snp",
			"nonce":            base64.RawURLEncoding.EncodeToString(nonce),
			"evidence":         map[string]any{"attestation_report": "AAAA"},
			"front_door_mode":  "cds",
			"cds_cert_pem":     id.chainPEM,
			"identity_proof":   id.proofJSON(t, v1),
			"route_digest":     hex.EncodeToString(testRouteDigest),
			"allowlist_digest": hex.EncodeToString(testAllowlistDigest),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromAttestLBJSON(data, nonce, serving, true, testRoute, "test"); !isSecurityError(err) {
			t.Fatalf("receipt over the v1 layout: err = %v, want a security error", err)
		}
	})
}

// TestV1BindingRefusedByVersion: a router still on the v1 binding is named
// by its version, not by a transcript mismatch.
func TestV1BindingRefusedByVersion(t *testing.T) {
	id := mintEndpointIdentity(t)
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	sess := fakeSession(0x10)
	var obj map[string]any
	if err := json.Unmarshal(buildEndpointJSON(t, id, nonce, bytes.Repeat([]byte{0x01}, 64), []byte("vcek"), sess), &obj); err != nil {
		t.Fatal(err)
	}
	obj["version"] = "c8s/attest-pq/v1"
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidenceFromEndpointJSON(data, nonce, sess.ek, testRoute, "test"); err == nil || isSecurityError(err) || !strings.Contains(err.Error(), "c8s/attest-pq/v2") {
		t.Fatalf("v1 bundle: err = %v, want a version refusal naming c8s/attest-pq/v2", err)
	}
}

// TestServedAllowlistDigest: the served value is what the transcript is
// recomputed with, so a forged one fails and a missing or malformed one is
// refused.
func TestServedAllowlistDigest(t *testing.T) {
	id := mintEndpointIdentity(t)
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	sess := fakeSession(0x10)
	withServed := func(served any) []byte {
		var obj map[string]any
		if err := json.Unmarshal(buildEndpointJSON(t, id, nonce, bytes.Repeat([]byte{0x01}, 64), []byte("vcek"), sess), &obj); err != nil {
			t.Fatal(err)
		}
		if served == nil {
			delete(obj, "allowlist_digest")
		} else {
			obj["allowlist_digest"] = served
		}
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	ev, err := evidenceFromEndpointJSON(withServed(hex.EncodeToString(testAllowlistDigest)), nonce, sess.ek, testRoute, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.allowlistDigest, testAllowlistDigest) {
		t.Fatalf("allowlistDigest = %x, want %x", ev.allowlistDigest, testAllowlistDigest)
	}

	forged := hex.EncodeToString(bytes.Repeat([]byte{0xb2}, 32))
	if _, err := evidenceFromEndpointJSON(withServed(forged), nonce, sess.ek, testRoute, "test"); !isSecurityError(err) {
		t.Fatalf("forged allowlist_digest: err = %v, want a security error", err)
	}
	for _, served := range []any{nil, "", strings.ToUpper(hex.EncodeToString(testAllowlistDigest)), "sha256:" + hex.EncodeToString(testAllowlistDigest), hex.EncodeToString(testAllowlistDigest[:31])} {
		if _, err := evidenceFromEndpointJSON(withServed(served), nonce, sess.ek, testRoute, "test"); err == nil || !strings.Contains(err.Error(), "allowlist_digest") {
			t.Fatalf("allowlist_digest %v: err = %v, want a refusal naming allowlist_digest", served, err)
		}
	}
}

func TestGatherFromAttestLBBindsAllowlistDigest(t *testing.T) {
	id := mintEndpointIdentity(t)
	ts := attestLBServer(t, id, nil)
	defer ts.Close()
	ev, err := gatherFromAttestLB(context.Background(), ts.URL, "", 5*time.Second, testRoute)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev.allowlistDigest, testAllowlistDigest) {
		t.Fatalf("allowlistDigest = %x, want %x", ev.allowlistDigest, testAllowlistDigest)
	}
}

func TestApplyAllowlistDigestPolicy(t *testing.T) {
	other := "sha256:" + strings.Repeat("b2", 32)
	for _, tc := range []struct {
		name         string
		pins         []string
		partial      bool
		wantVerified bool
		wantError    string
		wantNote     string
	}{
		{name: "unpinned is reported", wantVerified: true, wantNote: "reported"},
		{name: "pinned", pins: []string{testAllowlistPin}, wantVerified: true, wantNote: "pinned"},
		{name: "one of several pins", pins: []string{other, testAllowlistPin}, wantVerified: true, wantNote: "pinned"},
		{name: "wrong pin fails", pins: []string{other}, wantError: "allowlist_digest_not_pinned"},
		{name: "wrong pin fails a partial verdict", pins: []string{other}, partial: true, wantError: "allowlist_digest_not_pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oc := Outcome{Verified: !tc.partial, Partial: tc.partial}
			applyAllowlistDigestPolicy(&oc, config{allowlistDigests: tc.pins}, &evidence{allowlistDigest: testAllowlistDigest})
			if tc.wantError != "" {
				if oc.Verified || oc.Partial || !strings.Contains(oc.Error, tc.wantError) {
					t.Fatalf("outcome = %+v, want a failure with %q", oc, tc.wantError)
				}
				return
			}
			if oc.Verified != tc.wantVerified || oc.AllowlistDigest != testAllowlistPin || !strings.HasPrefix(oc.AllowlistNote, tc.wantNote) {
				t.Fatalf("outcome = %+v, want verified=%v, digest %s, note %q", oc, tc.wantVerified, testAllowlistPin, tc.wantNote)
			}
		})
	}
}

func TestAllowlistDigestFlagUsage(t *testing.T) {
	pin := hex.EncodeToString(testRouteDigest)
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{name: "bare hex", cfg: config{url: "https://router.invalid", mode: "attest-lb", routeDigests: []string{pin}, allowlistDigests: []string{hex.EncodeToString(testAllowlistDigest)}}, want: "is not sha256:<64 lowercase hex>"},
		{name: "upper case", cfg: config{url: "https://router.invalid", mode: "attest-lb", routeDigests: []string{pin}, allowlistDigests: []string{strings.ToUpper(testAllowlistPin)}}, want: "is not sha256:<64 lowercase hex>"},
		{name: "unattested mode", cfg: config{url: "https://router.invalid", mode: "armtls-cert", allowlistDigests: []string{testAllowlistPin}}, want: "applies only to --mode attest-pq"},
		{name: "expected report data", cfg: config{fromFile: "bundle.json", allowlistDigests: []string{testAllowlistPin}, expectedRDHex: "00"}, want: "does not apply with --expected-report-data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(context.Background(), tc.cfg, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("run = %d (%s), want %d with %q", code, errOut.String(), exitUsage, tc.want)
			}
		})
	}
}
