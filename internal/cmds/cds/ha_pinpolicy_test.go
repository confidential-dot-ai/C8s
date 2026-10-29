package cds

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// After a rollout the operator's policy must pin the new image under the
// launch keys of the old one: pin-policy writes exactly that from the
// replicas' applied decree, and refuses one it cannot authenticate.
func TestWritePinPolicy(t *testing.T) {
	h := func(c string) string { return strings.Repeat(c, 96) }
	oldImg := cdsha.DecreeImage{MRTD: h("a"), RTMR1: h("b"), RTMR2: h("c")}
	newImg := cdsha.DecreeImage{MRTD: h("d"), RTMR1: h("e"), RTMR2: h("f")}
	digest := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	_, serverKey := testKeyPEM(t)
	_, cdsKey := testKeyPEM(t)
	current := refvalues.ReferenceValues{Family: teetypes.FamilyTDX}
	for _, a := range []struct {
		name   string
		anchor []byte
	}{{"server", serverKey}, {"cds-1", cdsKey}} {
		current.Images = append(current.Images, remote.ImagePin{Name: a.name, Digest: digest(oldImg.MRTD),
			Registers: map[int][]byte{1: digest(oldImg.RTMR1), 2: digest(oldImg.RTMR2)}, Anchor: a.anchor})
	}
	k, decreePub := testKeyPEM(t)
	other, _ := testKeyPEM(t)
	block, _ := pem.Decode(decreePub)
	sign := func(key *ecdsa.PrivateKey, clusterID string) *cdsha.SignedDecree {
		pin, _ := newImg.Pin()
		sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "roll", BaseEpoch: 7, Kind: cdsha.UpdateMeasurements,
			ExpiresAt: time.Now().Add(time.Hour), Measurements: []string{pin}, Images: []cdsha.DecreeImage{newImg}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return &sd
	}
	var serve *cdsha.SignedDecree
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ha/pins" || serve == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(serve)
	}))
	defer ts.Close()
	dir := t.TempDir()
	run := func(out string) (string, error) {
		var buf bytes.Buffer
		err := writePinPolicy(t.Context(), ts.Client(), ts.URL, current, "c1", block.Bytes, out, "", &buf)
		return buf.String(), err
	}

	out := filepath.Join(dir, "server-next.json")
	serve = sign(k, "c1")
	printed, err := run(out)
	if err != nil || !strings.Contains(printed, "base_epoch=7 ") {
		t.Fatalf("%v: %s", err, printed)
	}
	pol, err := refvalues.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{string(serverKey): true, string(cdsKey): true}
	for _, p := range pol.Images {
		if !bytes.Equal(p.Digest, digest(newImg.MRTD)) || !bytes.Equal(p.Registers[1], digest(newImg.RTMR1)) {
			t.Fatalf("pin %s is not the decreed image", p.Name)
		}
		delete(want, string(p.Anchor))
	}
	if len(pol.Images) != 2 || len(want) != 0 {
		t.Fatalf("policy %+v does not pin the new image under both launch keys", pol.Images)
	}
	if _, err := run(out); err == nil {
		t.Fatal("an existing --out was overwritten")
	}
	// The written policy is the next rollout's starting point: the same
	// anchors, pin names that do not grow.
	var buf bytes.Buffer
	again := filepath.Join(dir, "server-again.json")
	if err := writePinPolicy(t.Context(), ts.Client(), ts.URL, pol, "c1", block.Bytes, again, "", &buf); err != nil {
		t.Fatal(err)
	}
	pol2, err := refvalues.Load(again)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pol2.Images {
		if pol2.Images[i].Name != pol.Images[i].Name || !bytes.Equal(pol2.Images[i].Anchor, pol.Images[i].Anchor) {
			t.Fatalf("pin %q became %q", pol.Images[i].Name, pol2.Images[i].Name)
		}
	}
	// Printing only, for the pin floor.
	if printed, err := run(""); err != nil || !strings.Contains(printed, "base_epoch=7") {
		t.Fatalf("print only: %v %s", err, printed)
	}
	// The signed decree itself, for add-cds-node --pin-decree.
	decreeOut := filepath.Join(dir, "pin-decree.json")
	if err := writePinPolicy(t.Context(), ts.Client(), ts.URL, current, "c1", block.Bytes, "", decreeOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var saved cdsha.SignedDecree
	if err := json.Unmarshal(must(os.ReadFile(decreeOut)), &saved); err != nil || cdsha.VerifyPinDecree(saved, "c1", block.Bytes) != nil || saved.Decree.IntentID != "roll" {
		t.Fatalf("--decree-out wrote %+v: %v", saved, err)
	}
	for name, sd := range map[string]*cdsha.SignedDecree{
		"no decree":     nil,
		"other signer":  sign(other, "c1"),
		"other cluster": sign(k, "c2"),
	} {
		serve = sd
		refused := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if _, err := run(refused); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(refused); err == nil {
			t.Errorf("%s: a policy was written", name)
		}
	}
	// The command needs the policy that pins the CDS it reads from.
	cmd := newHAPinPolicyCmd()
	cmd.SetArgs([]string{"--url", ts.URL, "--cluster-id", "c1", "--decree-public-key", filepath.Join(dir, "k.pem")})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--image-policy-file") {
		t.Fatalf("no --image-policy-file: %v", err)
	}
}
