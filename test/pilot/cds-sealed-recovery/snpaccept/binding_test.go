package snpaccept

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testLaunch(t *testing.T, authority, prefix string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{"schemaVersion": "c8s-cds/v1", "clusterID": "lane", "operatorPublicKeys": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
		"workloads": `{"schema":"c8s.allowlist/v1","workloads":{"test":{"containers":[{"digest":"sha256:` + strings.Repeat("11", 32) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`,
		"nodes":     `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + strings.Repeat("ab", 48) + `"}]}`,
		"nodeCIDRs": []string{"10.0.2.0/24"}, "ha": map[string]any{"replicas": []string{"127.0.77.1", "127.0.77.2", "127.0.77.3"}, "voters": 3, "objectWALPilot": map[string]any{"bucket": "pilot", "region": "local", "prefix": prefix, "endpoint": "https://127.0.0.1:9443", "pathStyle": true, "recoveryAuthority": authority}}}
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnrollmentOnlyOmitsAuthorityFromDerivation(t *testing.T) {
	a := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	b := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	launch := testLaunch(t, a, "owned-prefix")
	original, _, err := authorityContext(launch)
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := authorityContext(bytes.Replace(launch, []byte(a), []byte(b), 1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, changed) {
		t.Fatal("public enrollment dependency not resolved")
	}
	changed, _, err = authorityContext(bytes.Replace(launch, []byte("owned-prefix"), []byte("other-prefix"), 1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, changed) {
		t.Fatal("another cluster prefix shares authority derivation")
	}
	if _, _, err := authorityContext(append(launch, []byte("unknown: true\n")...)); err == nil {
		t.Fatal("unknown measured setting accepted")
	}
}

func TestAttestationCannotPretendToEnforceTDXOrDebug(t *testing.T) {
	api := AttestationAPI(nil, nil)
	for _, body := range []string{
		`{"platform":"tdx","evidence":{}}`,
		`{"platform":"sev-snp","evidence":{},"params":{"allow_debug":true}}`,
		`{"platform":"sev-snp","evidence":{},"params":{"expected_mrtd":"AQ=="}}`,
		`{"platform":"sev-snp","evidence":{},"issue_token":true}`,
		`{"platform":"sev-snp","evidence":{"attestation_report":"AA=="}}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(body))
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("unverifiable request accepted: %d", w.Code)
		}
	}
}

func TestEvidenceBindsEntirePhaseAndResult(t *testing.T) {
	q := Request{Operation: "recover", Nonce: bytes.Repeat([]byte{1}, 32), Measurement: strings.Repeat("ab", 48)}
	r := Result{Operation: "recover", Passed: true, Checks: map[string]any{"ca": "first"}}
	original := Binding(q, r)
	r.Checks["ca"] = "different"
	if Binding(q, r) == original {
		t.Fatal("CA result substitution unbound")
	}
	r.Checks["ca"] = "first"
	q.Nonce[0]++
	if Binding(q, r) == original {
		t.Fatal("response replay unbound")
	}
}
