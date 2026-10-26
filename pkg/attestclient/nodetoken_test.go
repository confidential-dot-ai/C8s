package attestclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestObtainNodeToken_BindsEvidenceToNodeKey(t *testing.T) {
	const challenge = "dGVzdC1jaGFsbGVuZ2U="
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var reportData []byte
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ReportData []byte `json:"report_data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reportData = req.ReportData
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{"q":1}}`))
	}))
	t.Cleanup(api.Close)

	expires := time.Now().Add(5 * time.Minute).Truncate(time.Second).UTC()
	var sent types.NodeTokenRequestBody
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: challenge})
	})
	mux.HandleFunc("POST "+NodeTokenPath, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		_ = json.NewEncoder(w).Encode(types.NodeTokenResponse{Token: "tok", ExpiresAt: expires})
	})
	cds := httptest.NewServer(mux)
	t.Cleanup(cds.Close)

	resp, err := NewClient(cds.URL).ObtainNodeToken(context.Background(), api.URL, &key.PublicKey, "cl-1.k8s.example.test")
	if err != nil {
		t.Fatalf("ObtainNodeToken: %v", err)
	}
	if resp.Token != "tok" || !resp.ExpiresAt.Equal(expires) {
		t.Fatalf("response %+v", resp)
	}

	raw, _ := base64.StdEncoding.DecodeString(challenge)
	want, err := armtls.ReportDataForKey(&key.PublicKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reportData, want[:sha512.Size384]) {
		t.Fatalf("report_data %x, want SHA-384(node key || challenge)", reportData)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if sent.NodeKey != base64.StdEncoding.EncodeToString(der) || sent.Audience != "cl-1.k8s.example.test" ||
		sent.Challenge != challenge || sent.Evidence.Platform != "snp" {
		t.Fatalf("request %+v", sent)
	}
}

func TestObtainNodeToken_RefusesEmptyResponse(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{"q":1}}`))
	}))
	t.Cleanup(api.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(types.ChallengeResponse{Challenge: "AAAA"})
	})
	mux.HandleFunc(NodeTokenPath, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	cds := httptest.NewServer(mux)
	t.Cleanup(cds.Close)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewClient(cds.URL).ObtainNodeToken(context.Background(), api.URL, &key.PublicKey, "a"); err == nil {
		t.Fatal("accepted a response with no token")
	}
}
