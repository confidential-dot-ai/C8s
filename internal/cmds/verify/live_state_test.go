package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/rolloutstate"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// expiredState is a correctly signed, nonce-bound state whose validity window
// has passed.
func expiredState(t *testing.T, id *endpointIdentity, nonce []byte) *types.SignedRolloutState {
	t.Helper()
	st := types.RolloutState{Protocol: 1, Bound: []string{"sha256:p"}, Lease: 30, Nonce: hex.EncodeToString(nonce)}
	rolloutstate.Stamp(&st, time.Now().Add(-time.Hour))
	return signRolloutState(t, id.caKey, st)
}

// Live attest-pq and attest-lb bundles time-check their state; a saved
// attest-pq bundle does not.
func TestEvidenceTimeChecksLiveState(t *testing.T) {
	id := mintEndpointIdentity(t)
	nonce := bytes.Repeat([]byte{0x05}, nonceSize)
	state := expiredState(t, id, nonce)
	b64u := base64.RawURLEncoding.EncodeToString

	s := fakeSession(0x10)
	pqTranscript, err := overenc.IdentityTranscriptHash("cds", s.ek, s.ct, s.sid, nonce, id.leaf.Raw, id.ca.Raw, overenc.StateDigest(state.State))
	if err != nil {
		t.Fatal(err)
	}
	pq, err := json.Marshal(map[string]any{
		"version": types.BindingAttestPQ, "platform": "snp", "nonce": b64u(nonce),
		"evidence":        map[string]any{"attestation_report": "AAAA", "cert_chain": map[string]any{"vcek": "AAAA"}},
		"front_door_mode": "cds", "xwing_ek": b64u(s.ek), "xwing_ct": b64u(s.ct), "session_id": b64u(s.sid),
		"cds_cert_pem": id.chainPEM, "identity_proof": id.proofJSON(t, pqTranscript), "cds_state": state,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidenceFromEndpointJSON(pq, nonce, s.ek, "test")
	if err != nil {
		t.Fatal(err)
	}
	if ev.rolloutErr == nil || !strings.Contains(ev.rolloutErr.Error(), "expired") {
		t.Fatalf("live attest-pq: rolloutErr = %v, want expired", ev.rolloutErr)
	}
	ev, err = evidenceFromEndpointJSON(pq, nil, nil, "file")
	if err != nil {
		t.Fatal(err)
	}
	if ev.rolloutErr != nil {
		t.Fatalf("saved attest-pq bundle: rolloutErr = %v, want none", ev.rolloutErr)
	}

	servingLeaf := []byte("serving leaf")
	lbTranscript, err := overenc.LBTranscriptHash(types.FrontDoorModeCDS, nonce, servingLeaf, id.leaf.Raw, id.ca.Raw, overenc.StateDigest(state.State))
	if err != nil {
		t.Fatal(err)
	}
	lb, err := json.Marshal(map[string]any{
		"version": types.BindingAttestLB, "platform": "snp", "nonce": b64u(nonce),
		"evidence": map[string]any{"attestation_report": "AAAA"}, "front_door_mode": "cds",
		"cds_cert_pem": id.chainPEM, "identity_proof": id.proofJSON(t, lbTranscript), "cds_state": state,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err = evidenceFromAttestLBJSON(lb, nonce, servingLeaf, "test")
	if err != nil {
		t.Fatal(err)
	}
	if ev.rolloutErr == nil || !strings.Contains(ev.rolloutErr.Error(), "expired") {
		t.Fatalf("live attest-lb: rolloutErr = %v, want expired", ev.rolloutErr)
	}
}
