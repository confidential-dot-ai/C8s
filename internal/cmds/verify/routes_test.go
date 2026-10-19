package verify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testRouteDigest is the route digest every test fixture binds.
var testRouteDigest = bytes.Repeat([]byte{0x5a}, 32)

// testRoute pins testRouteDigest, as --route-digest would.
var testRoute = &boundRoute{digest: testRouteDigest, note: "pinned: matches --route-digest"}

func TestParseRouteCheck(t *testing.T) {
	pin := hex.EncodeToString(testRouteDigest)
	for _, tc := range []struct {
		name     string
		cfg      config
		wantPins int
		wantErr  string
		// notErr is a flag the usage error must not offer.
		notErr string
	}{
		{name: "discovery checks none", cfg: config{mode: "discovery"}},
		{name: "auto checks none", cfg: config{}},
		{name: "attest-pq without a route check", cfg: config{mode: "attest-pq"}, wantErr: "pass --route-digest HEX (from `c8s routes show`) or --operator-keys"},
		{name: "attest-lb without a route check", cfg: config{mode: "attest-lb"}, wantErr: "pass --route-digest HEX (from `c8s routes show`) or --operator-keys"},
		{name: "attest-pq pinned", cfg: config{mode: "attest-pq", routeDigests: []string{pin}}, wantPins: 1},
		{name: "attest-lb pinned", cfg: config{mode: "attest-lb", routeDigests: []string{pin}}, wantPins: 1},
		{name: "saved bundle pinned", cfg: config{fromFile: "bundle.json", routeDigests: []string{pin}}, wantPins: 1},
		{name: "two pins", cfg: config{mode: "attest-pq", routeDigests: []string{pin, strings.Repeat("6b", 32)}}, wantPins: 2},
		{name: "saved attest-pq bundle without a route check", cfg: config{mode: "attest-pq", fromFile: "bundle.json"}, wantErr: "pass --route-digest HEX (from `c8s routes show`)", notErr: "--operator-keys"},
		{name: "pin on discovery", cfg: config{mode: "discovery", routeDigests: []string{pin}}, wantErr: "applies only to"},
		{name: "pin not hex", cfg: config{mode: "attest-pq", routeDigests: []string{"zz"}}, wantErr: "not hex"},
		{name: "pin short", cfg: config{mode: "attest-pq", routeDigests: []string{pin[:62]}}, wantErr: "31 bytes, want 32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := parseRouteCheck(tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseRouteCheck = %v, want %q", err, tc.wantErr)
				}
				if tc.notErr != "" && strings.Contains(err.Error(), tc.notErr) {
					t.Fatalf("parseRouteCheck = %v, want no mention of %s", err, tc.notErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			if rc != nil {
				got = len(rc.pins)
			}
			if got != tc.wantPins || got > 0 && !bytes.Equal(rc.pins[0], testRouteDigest) {
				t.Fatalf("parseRouteCheck pins = %d, want %d starting with the first --route-digest", got, tc.wantPins)
			}
		})
	}
}

func TestRouteDigestRequiredInAttestedModes(t *testing.T) {
	for _, mode := range []string{"attest-pq", "attest-lb"} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), config{url: "https://127.0.0.1:1", mode: mode}, &out, &errOut); code != exitUsage {
			t.Fatalf("run(--mode %s, no route check) = %d, want %d", mode, code, exitUsage)
		}
		if !strings.Contains(errOut.String(), "--route-digest") {
			t.Fatalf("run(--mode %s) stderr = %q, want it to name --route-digest", mode, errOut.String())
		}
	}
}

// TestV1RouteDigestPin covers V1: report_data binds the pinned digest, or the
// transcript fails, whatever the bundle's informational field says.
func TestV1RouteDigestPin(t *testing.T) {
	id := mintEndpointIdentity(t)
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	sess := fakeSession(0x10)
	data := buildEndpointJSON(t, id, nonce, bytes.Repeat([]byte{0x01}, 64), []byte("vcek"), sess)
	withServed := func(served string) []byte {
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			t.Fatal(err)
		}
		obj["route_digest"] = served
		b, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	other := &boundRoute{digest: bytes.Repeat([]byte{0x6b}, 32), note: "pinned: matches --route-digest"}

	t.Run("match", func(t *testing.T) {
		ev, err := evidenceFromEndpointJSON(withServed(hex.EncodeToString(testRouteDigest)), nonce, sess.ek, testRoute, "test")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ev.erd, id.transcript(t, nonce, sess)) || ev.route != testRoute {
			t.Fatal("evidence does not bind the pinned route digest")
		}
	})
	t.Run("served digest differs from the pin", func(t *testing.T) {
		_, err := evidenceFromEndpointJSON(withServed(hex.EncodeToString(other.digest)), nonce, sess.ek, testRoute, "test")
		if !isSecurityError(err) || !strings.Contains(err.Error(), "route digest mismatch") || strings.Contains(err.Error(), testRoute.note) {
			t.Fatalf("err = %v, want a route digest mismatch security error without the success note", err)
		}
	})
	t.Run("served digest is one of several pins", func(t *testing.T) {
		pins := &boundRoute{digest: other.digest, alternatives: [][]byte{testRouteDigest}, note: testRoute.note}
		ev, err := evidenceFromEndpointJSON(withServed(hex.EncodeToString(testRouteDigest)), nonce, sess.ek, pins, "test")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ev.route.digest, testRouteDigest) {
			t.Fatalf("bound route digest %x, want %x", ev.route.digest, testRouteDigest)
		}
	})
	for name, served := range map[string]string{
		"no served digest":         "",
		"upper-case served digest": strings.ToUpper(hex.EncodeToString(testRouteDigest)),
		"short served digest":      hex.EncodeToString(testRouteDigest[:31]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := evidenceFromEndpointJSON(withServed(served), nonce, sess.ek, testRoute, "test"); err == nil || !strings.Contains(err.Error(), "route_digest") {
				t.Fatalf("err = %v, want a refusal naming route_digest", err)
			}
		})
	}
	t.Run("pin differs and the served field agrees with it", func(t *testing.T) {
		// The responder cannot talk a client into a digest by echoing its pin:
		// report_data binds testRouteDigest, so the proof over other fails.
		_, err := evidenceFromEndpointJSON(withServed(hex.EncodeToString(other.digest)), nonce, sess.ek, other, "test")
		if !isSecurityError(err) {
			t.Fatalf("err = %v, want a security error", err)
		}
	})
	t.Run("no route check", func(t *testing.T) {
		if _, err := evidenceFromEndpointJSON(data, nonce, sess.ek, nil, "test"); err == nil || !strings.Contains(err.Error(), "--route-digest") {
			t.Fatalf("err = %v, want a refusal naming --route-digest", err)
		}
	})
}

func TestV1RouteDigestPinAttestLB(t *testing.T) {
	ts := attestLBServer(t, mintEndpointIdentity(t), nil)
	defer ts.Close()
	if _, err := gatherFromAttestLB(context.Background(), ts.URL, "", 5*time.Second, testRoute); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	other := &boundRoute{digest: bytes.Repeat([]byte{0x6b}, 32)}
	if _, err := gatherFromAttestLB(context.Background(), ts.URL, "", 5*time.Second, other); !isSecurityError(err) {
		t.Fatalf("other pin: err = %v, want a security error", err)
	}
}

// operatorSigner is an operator key pair with its public half in a PEM file.
type operatorSigner struct {
	key     *ecdsa.PrivateKey
	signer  *operatorauth.Signer
	keys    []*ecdsa.PublicKey
	keyFile string
}

func newOperatorSigner(t *testing.T) operatorSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return operatorSigner{key: key, signer: signer, keys: []*ecdsa.PublicKey{&key.PublicKey}, keyFile: keyFile}
}

// publish signs a manifest at revision and returns the publication body and
// the manifest's route digest.
func (o operatorSigner) publish(t *testing.T, revision int) ([]byte, []byte) {
	t.Helper()
	manifest := []byte(`{"schema":"c8s.routes/v1","revision":` + strconv.Itoa(revision) + `,"notBefore":"2020-01-01T00:00:00Z","maxAgeSeconds":3600,"hosts":{}}`)
	auth, err := o.signer.Authorization(http.MethodPut, routes.Path, manifest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(routes.Envelope{Manifest: manifest, Token: strings.TrimPrefix(auth, "Bearer ")})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifest)
	return body, digest[:]
}

func TestParseRouteCheckV2(t *testing.T) {
	op := newOperatorSigner(t)
	pin := hex.EncodeToString(testRouteDigest)
	for _, tc := range []struct {
		name      string
		cfg       config
		wantFloor uint64
		wantErr   string
	}{
		{name: "keys", cfg: config{mode: "attest-lb", operatorKeys: op.keyFile}},
		{name: "keys and floor", cfg: config{mode: "attest-pq", operatorKeys: op.keyFile, routesFloor: "7:" + pin}, wantFloor: 7},
		{name: "keys and pin", cfg: config{mode: "attest-pq", operatorKeys: op.keyFile, routeDigests: []string{pin}}, wantErr: "pass one of"},
		{name: "floor without keys", cfg: config{mode: "attest-pq", routeDigests: []string{pin}, routesFloor: "7:" + pin}, wantErr: "only with --operator-keys"},
		{name: "floor outside attested modes", cfg: config{mode: "discovery", routesFloor: "7:" + pin}, wantErr: "applies only to"},
		{name: "keys with kind cds", cfg: config{kind: "cds", mode: "attest-pq", operatorKeys: op.keyFile}, wantErr: "drop --kind cds"},
		{name: "keys with a saved file", cfg: config{mode: "attest-lb", fromFile: "receipt.json", operatorKeys: op.keyFile}, wantErr: "pass --route-digest"},
		{name: "floor without a colon", cfg: config{mode: "attest-pq", operatorKeys: op.keyFile, routesFloor: pin}, wantErr: "want <revision>"},
		{name: "floor revision zero", cfg: config{mode: "attest-pq", operatorKeys: op.keyFile, routesFloor: "0:" + pin}, wantErr: "positive integer"},
		{name: "floor digest short", cfg: config{mode: "attest-pq", operatorKeys: op.keyFile, routesFloor: "3:abcd"}, wantErr: "2 bytes"},
		{name: "keys file missing", cfg: config{mode: "attest-pq", operatorKeys: filepath.Join(t.TempDir(), "absent")}, wantErr: "read --operator-keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := parseRouteCheck(tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseRouteCheck = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rc.keys) != 1 || rc.pins != nil {
				t.Fatalf("parseRouteCheck = %+v, want one operator key and no pin", rc)
			}
			if got := uint64(0); rc.floor != nil {
				got = rc.floor.revision
				if got != tc.wantFloor {
					t.Fatalf("floor revision = %d, want %d", got, tc.wantFloor)
				}
			} else if tc.wantFloor != 0 {
				t.Fatal("no floor parsed")
			}
		})
	}
}

// The re-fetch after a digest mismatch accepts any manifest that passes the
// checks, whatever its revision relative to the first fetch, as the clients do.
func TestV2RefetchAcceptsAnyRevision(t *testing.T) {
	op := newOperatorSigner(t)
	newer, _ := op.publish(t, 5)
	older, _ := op.publish(t, 3)
	newest, _ := op.publish(t, 6)
	var served [][]byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(served[0])
		served = served[1:]
	}))
	t.Cleanup(ts.Close)

	served = [][]byte{newer, older, newer, newest}
	route, err := (&routeCheck{keys: op.keys}).bind(context.Background(), ts.URL, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := route.refetch(); err != nil || fresh.revision != 3 {
		t.Fatalf("refetch of revision 3 after 5 = %+v, %v, want revision 3", fresh, err)
	}
	route, err = (&routeCheck{keys: op.keys}).bind(context.Background(), ts.URL, "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := route.refetch(); err != nil || fresh.revision != 6 {
		t.Fatalf("refetch of revision 6 after 5 = %+v, %v, want revision 6", fresh, err)
	}
}

// TestV2PublishedManifest covers V2 against an attest-lb responder that
// publishes a signed manifest and binds a route digest.
func TestV2PublishedManifest(t *testing.T) {
	id := mintEndpointIdentity(t)
	op := newOperatorSigner(t)
	publication, digest := op.publish(t, 3)
	ctx := context.Background()
	gather := func(t *testing.T, rc *routeCheck, bound, published []byte) (*evidence, error) {
		t.Helper()
		ts := routedLBServer(t, id, nil, bound, published)
		t.Cleanup(ts.Close)
		route, err := rc.bind(ctx, ts.URL, "", 5*time.Second)
		if err != nil {
			return nil, err
		}
		return gatherFromAttestLB(ctx, ts.URL, "", 5*time.Second, route)
	}

	t.Run("verifies", func(t *testing.T) {
		ev, err := gather(t, &routeCheck{keys: op.keys}, digest, publication)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ev.route.digest, digest) || ev.route.revision != 3 || !strings.Contains(ev.route.note, "operator-signed") {
			t.Fatalf("route = %+v, want the published digest at revision 3, operator-signed", ev.route)
		}
	})
	t.Run("untrusted key", func(t *testing.T) {
		_, err := gather(t, &routeCheck{keys: newOperatorSigner(t).keys}, digest, publication)
		if !isSecurityError(err) || !strings.Contains(err.Error(), "does not verify under --operator-keys") {
			t.Fatalf("err = %v, want a signature security error", err)
		}
	})
	t.Run("transcript binds another digest", func(t *testing.T) {
		_, err := gather(t, &routeCheck{keys: op.keys}, testRouteDigest, publication)
		if !isSecurityError(err) {
			t.Fatalf("err = %v, want a security error", err)
		}
	})
	t.Run("floor accepts the same manifest", func(t *testing.T) {
		floor := &routeFloor{revision: 3, digest: [32]byte(digest)}
		if _, err := gather(t, &routeCheck{keys: op.keys, floor: floor}, digest, publication); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("floor refuses a rollback", func(t *testing.T) {
		floor := &routeFloor{revision: 4, digest: [32]byte(digest)}
		_, err := gather(t, &routeCheck{keys: op.keys, floor: floor}, digest, publication)
		if !isSecurityError(err) || !errors.Is(err, routes.ErrRollback) {
			t.Fatalf("err = %v, want a W4 rollback", err)
		}
	})
	t.Run("floor refuses another manifest at its revision", func(t *testing.T) {
		floor := &routeFloor{revision: 3, digest: [32]byte(testRouteDigest)}
		_, err := gather(t, &routeCheck{keys: op.keys, floor: floor}, digest, publication)
		if !isSecurityError(err) || !errors.Is(err, routes.ErrRevisionConflict) {
			t.Fatalf("err = %v, want a W4 revision conflict", err)
		}
	})
	t.Run("time claims and notBefore are not checked", func(t *testing.T) {
		manifest := []byte(`{"schema":"c8s.routes/v1","revision":5,"notBefore":"2999-01-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`)
		pbh := sha256.Sum256(manifest)
		signed := time.Now().Add(-90 * 24 * time.Hour)
		token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iat": signed.Unix(), "exp": signed.Add(time.Minute).Unix(), "nbf": time.Now().Add(time.Hour).Unix(),
			"htm": http.MethodPut, "htu": routes.Path, "pbh": base64.RawURLEncoding.EncodeToString(pbh[:]),
		}).SignedString(op.key)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(routes.Envelope{Manifest: manifest, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gather(t, &routeCheck{keys: op.keys}, pbh[:], body); err != nil {
			t.Fatalf("gather = %v, want a stored token and staged manifest to verify", err)
		}
	})
	t.Run("publication disabled", func(t *testing.T) {
		_, err := gather(t, &routeCheck{keys: op.keys}, digest, nil)
		if !isConnectError(err) || !strings.Contains(err.Error(), "--route-digest") {
			t.Fatalf("err = %v, want a connect error suggesting --route-digest", err)
		}
	})
	t.Run("publication not an envelope", func(t *testing.T) {
		_, err := gather(t, &routeCheck{keys: op.keys}, digest, []byte(`{"manifest":"e30="}`))
		if err == nil || isSecurityError(err) || isConnectError(err) {
			t.Fatalf("err = %v, want a plain parse error", err)
		}
	})
}

func TestRouteVerdictRendered(t *testing.T) {
	var out bytes.Buffer
	renderText(config{}, Outcome{Verified: true, RouteDigest: hex.EncodeToString(testRouteDigest), RouteRevision: 3, RouteNote: "operator-signed: test"}, &out)
	for _, want := range []string{"route digest: " + hex.EncodeToString(testRouteDigest), "route rev:    3", "operator-signed: test"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("verdict output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestSavedBundleRouteFlags(t *testing.T) {
	id := mintEndpointIdentity(t)
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	data := buildEndpointJSON(t, id, bytes.Repeat([]byte{0x07}, nonceSize), bytes.Repeat([]byte{0x01}, 64), []byte("vcek"), fakeSession(0x10))
	if err := os.WriteFile(bundle, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), config{fromFile: bundle}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "--route-digest") {
		t.Fatalf("saved attest-pq bundle without --route-digest = %d (%s), want %d naming --route-digest", code, errOut.String(), exitUsage)
	}

	cert := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(cert, certutil.EncodeCertPEM(mintForgedIssuerLeaf(t, &id.key.PublicKey, time.Now().Add(time.Hour)).Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := hex.EncodeToString(testRouteDigest)
	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{name: "certificate", cfg: config{fromFile: cert, routeDigests: []string{pin}}, want: "does not apply to a certificate"},
		{name: "expected report data", cfg: config{fromFile: bundle, routeDigests: []string{pin}, expectedRDHex: "00"}, want: "do not apply with --expected-report-data"},
		{name: "expected report data on an attest-lb receipt", cfg: config{mode: "attest-lb", fromFile: bundle, observedServingCert: cert, attestationNonce: base64.RawURLEncoding.EncodeToString(make([]byte, nonceSize)), expectedRDHex: "00"}, want: "does not apply to --mode attest-lb"},
		{name: "expected report data in attest-pq mode", cfg: config{mode: "attest-pq", fromFile: bundle, routeDigests: []string{pin}, expectedRDHex: "00"}, want: "does not apply to --mode attest-pq"},
		{name: "expected report data in attest-pq mode without a route check", cfg: config{mode: "attest-pq", fromFile: bundle, expectedRDHex: "00"}, want: "does not apply to --mode attest-pq"},
		{name: "expected report data against a live router", cfg: config{url: "https://router.invalid", mode: "attest-lb", routeDigests: []string{pin}, expectedRDHex: "00"}, want: "does not apply to --mode attest-lb"},
		{name: "operator keys with kind cds", cfg: config{url: "https://router.invalid", kind: "cds", mode: "attest-pq", operatorKeys: newOperatorSigner(t).keyFile}, want: "drop --kind cds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(context.Background(), tc.cfg, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("run = %d (%s), want %d with %q", code, errOut.String(), exitUsage, tc.want)
			}
		})
	}
}

// transcriptOf hashes length-prefixed fields the way both transcripts do, so
// a test can sign a layout the verifier must not accept.
func transcriptOf(fields ...[]byte) []byte {
	var encoded []byte
	for _, field := range fields {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		encoded = append(append(encoded, size[:]...), field...)
	}
	sum := sha512.Sum384(encoded)
	return sum[:]
}

func sum256(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// TestTranscriptWithoutRouteDigestRejected signs the transcript layout that
// lacks the route digest under the current binding id: the id alone must not
// verify.
func TestTranscriptWithoutRouteDigestRejected(t *testing.T) {
	id := mintEndpointIdentity(t)
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)

	t.Run("attest-pq", func(t *testing.T) {
		sess := fakeSession(0x10)
		var obj map[string]any
		if err := json.Unmarshal(buildEndpointJSON(t, id, nonce, bytes.Repeat([]byte{0x01}, 64), []byte("vcek"), sess), &obj); err != nil {
			t.Fatal(err)
		}
		short := transcriptOf([]byte(types.ProtocolVersion), []byte("cds"), sum256(id.ca.Raw), sum256(id.leaf.Raw), sess.ek, sess.ct, sess.sid, nonce)
		obj["identity_proof"] = id.proofJSON(t, short)
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromEndpointJSON(data, nonce, sess.ek, testRoute, "test"); !isSecurityError(err) {
			t.Fatalf("bundle over a transcript without the route digest: err = %v, want a security error", err)
		}
	})
	t.Run("attest-lb", func(t *testing.T) {
		serving := []byte("serving-der")
		short := transcriptOf([]byte(types.BindingAttestLB), []byte("cds"), nonce, sum256(serving), sum256(id.leaf.Raw), sum256(id.ca.Raw))
		data, err := json.Marshal(map[string]any{
			"version":         types.BindingAttestLB,
			"platform":        "snp",
			"nonce":           base64.RawURLEncoding.EncodeToString(nonce),
			"evidence":        map[string]any{"attestation_report": "AAAA"},
			"front_door_mode": "cds",
			"cds_cert_pem":    id.chainPEM,
			"identity_proof":  id.proofJSON(t, short),
			"route_digest":    hex.EncodeToString(testRouteDigest),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evidenceFromAttestLBJSON(data, nonce, serving, true, testRoute, "test"); !isSecurityError(err) {
			t.Fatalf("receipt over a transcript without the route digest: err = %v, want a security error", err)
		}
	})
}
