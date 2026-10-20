package cds

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestAttestKeepsNodeOperatorBoundToImage(t *testing.T) {
	digest := make([]byte, 48)
	digest[0] = 0xaa
	server, agent := []byte("server key"), []byte("agent key")
	stub := newStubAttestationApi(t, hex.EncodeToString(digest))
	h := newTestAttestHandler(t, stub.URL(), nil)
	h.Images = []remote.ImagePin{{Name: "server", Digest: digest, Anchor: server}}
	csr, _ := generateCSR(t)
	for _, tc := range []struct {
		name   string
		key    []byte
		status int
	}{
		{"server", server, http.StatusOK}, {"same image wrong operator", agent, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := mockapi.PassingVerdict(hex.EncodeToString(digest))
			binding := runtimemeasure.HostData(tc.key)
			verdict.Claims.InitData = binding[:]
			stub.SetVerdict(verdict)
			response := postAttest(t, h, issueChallenge(t, h), csr)
			if response.Code != tc.status {
				t.Fatalf("status=%d want=%d: %s", response.Code, tc.status, response.Body.String())
			}
		})
	}
}

func TestCDSConfigPreservesNodeKeys(t *testing.T) {
	got, err := cmdsutil.LoadImagePolicyValues(cmdsutil.ImagePolicyValuesConfig{
		Source:   cmdsutil.ImagePolicySource{File: "../../../internal/testdata/node-identities.json"},
		Platform: "tdx",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Images) != 2 || !got.HasAnchors() {
		t.Fatal("CDS startup dropped node identities")
	}
	encoded, err := refvalues.Format(got)
	if err != nil {
		t.Fatal(err)
	}
	served, err := refvalues.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	missing, extra := refvalues.Diff(got, served)
	if len(missing)+len(extra) != 0 {
		t.Fatal("served policy dropped identities")
	}
}

func TestAttestReplaysRuntimeExtensions(t *testing.T) {
	digest := mustDecode(t, testMRTD)
	anchor := []byte("server key")
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	stub := newStubAttestationApi(t, testMRTD)
	h := newTestAttestHandler(t, stub.URL(), nil)
	h.Images = []remote.ImagePin{{Name: "server", Digest: digest, Anchor: anchor}}
	csr, _ := generateCSR(t)
	for _, tc := range []struct {
		name     string
		extended []string
		claimed  []string
		status   int
	}{
		{"bare seed, no list", nil, nil, http.StatusOK},
		{"replaying list", []string{p}, []string{p, q}, http.StatusOK},
		{"extended, no list", []string{p}, nil, http.StatusForbidden},
		{"list does not replay", []string{q}, []string{p}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := tdxVerdict(t, testMRTD, testRTMR1, testRTMR2)
			reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), tc.extended)
			verdict.Claims.PlatformData["rtmr_3"] = hex.EncodeToString(reg[:])
			stub.SetVerdict(verdict)
			body, err := json.Marshal(types.AttestRequestBody{
				Challenge:         issueChallenge(t, h),
				Evidence:          teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"abc"}`)},
				CSR:               csr,
				RuntimeExtensions: tc.claimed,
			})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.HandleAttest(w, httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body)))
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}
