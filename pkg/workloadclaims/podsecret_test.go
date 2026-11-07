package workloadclaims

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakePodSecretCDS answers as CDS does after verification: it recomputes the
// binding from the request and seals to the bound key.
type fakePodSecretCDS struct {
	nonce    []byte
	quoted   []byte
	value    []byte
	readers  []string
	tamper   func(*PodSecretRequest)
	requests []PodSecretRequest
}

func (f *fakePodSecretCDS) GenerateEvidenceContext(_ context.Context, _ string, reportData []byte) (remote.AttestResponse, error) {
	f.quoted = bytes.Clone(reportData)
	return remote.AttestResponse{Platform: "tdx", Evidence: json.RawMessage(`{"quote":"fake"}`)}, nil
}

func (f *fakePodSecretCDS) PostJSON(_ context.Context, path string, body []byte) ([]byte, error) {
	switch path {
	case PodSecretChallengeRoute:
		f.nonce = make([]byte, 32)
		_, _ = rand.Read(f.nonce)
		return json.Marshal(types.ChallengeResponse{Challenge: base64.StdEncoding.EncodeToString(f.nonce)})
	case PodSecretRoute:
		var req PodSecretRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		f.requests = append(f.requests, req)
		binding, err := PodSecretReportData(req.ResponseKey, f.nonce, req.PodClaims, req.Path)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(binding, f.quoted) {
			return nil, fmt.Errorf("quote does not bind the request")
		}
		if f.tamper != nil {
			f.tamper(&req)
			binding, _ = PodSecretReportData(req.ResponseKey, f.nonce, req.PodClaims, req.Path)
		}
		sealed, err := SealPodSecret(req.ResponseKey, binding, f.value)
		if err != nil {
			return nil, err
		}
		return json.Marshal(PodSecretResponse{Workload: "user-a", Readers: f.readers, Sealed: sealed})
	}
	return nil, fmt.Errorf("unexpected path %s", path)
}

func TestObtainPodSecretBindsAndOpens(t *testing.T) {
	claims := testPodClaims(t)
	cds := &fakePodSecretCDS{value: []byte("per-user data key"), readers: []string{claims.RuntimeExtensions[0]}}
	got, err := ObtainPodSecretContext(context.Background(), cds, "http://attest", "/users/a/key", claims)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Value) != "per-user data key" || got.Workload != "user-a" || got.Path != "/users/a/key" {
		t.Fatalf("got %+v", got)
	}
	canonical, _ := claims.Canonical()
	if !bytes.Equal(cds.requests[0].PodClaims, canonical) {
		t.Fatal("request does not carry the canonical claims")
	}
}

// A value sealed for any other binding does not open: a response for another
// path or another snapshot is useless to the broker.
func TestObtainPodSecretRefusesForeignBinding(t *testing.T) {
	claims := testPodClaims(t)
	cds := &fakePodSecretCDS{value: []byte("v"), readers: []string{claims.RuntimeExtensions[0]},
		tamper: func(r *PodSecretRequest) { r.Path = "/users/b/key" }}
	if _, err := ObtainPodSecretContext(context.Background(), cds, "http://attest", "/users/a/key", claims); err == nil {
		t.Fatal("opened a value sealed for another path")
	}
	cds = &fakePodSecretCDS{value: []byte("v")}
	if _, err := ObtainPodSecretContext(context.Background(), cds, "http://attest", "/users/a/key", claims); err == nil {
		t.Fatal("accepted a release that names no reader")
	}
}

func TestPodSecretReportDataSeparatesInputs(t *testing.T) {
	claims := testPodClaims(t)
	canonical, _ := claims.Canonical()
	priv, _ := podSecretKEM().GenerateKey()
	key := priv.PublicKey().Bytes()
	nonce := bytes.Repeat([]byte{1}, 32)
	a, err := PodSecretReportData(key, nonce, canonical, "/a")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := PodSecretReportData(key, nonce, canonical, "/b")
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrBinding, _ := PodReportData(&ecKey.PublicKey, nonce, canonical)
	if bytes.Equal(a, b) || bytes.Equal(a, csrBinding) || len(a) != 48 {
		t.Fatal("binding does not separate path or profile")
	}
	if _, err := PodSecretReportData([]byte("short"), nonce, canonical, "/a"); err == nil {
		t.Fatal("accepted an invalid response key")
	}
}
