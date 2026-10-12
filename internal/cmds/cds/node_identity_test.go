package cds

import (
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestAttestKeepsNodeOperatorBoundToImage(t *testing.T) {
	digest := make([]byte, 48)
	digest[0] = 0xaa
	server, agent := []byte("server key"), []byte("agent key")
	stub := newStubAttestationApi(t, hex.EncodeToString(digest))
	h := newPinnedAttestHandler(t, stub.URL(), armtls.Pins{
		Images: []remote.ImagePin{{Name: "server", Digest: digest, Anchor: server}},
	})
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
