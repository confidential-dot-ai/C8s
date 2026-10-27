package cds

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// recover hands the decrypted cluster state (mesh CA key, every secret) to
// the endpoint: in a release build it goes only to one whose whole image
// identity the operator's image policy pins, launch-key anchor and, on TDX,
// RTMR1/2 included. A launch digest alone (TDX: the firmware) or plaintext
// gets no request at all.
func TestHARecoverRefusesWeakPins(t *testing.T) {
	if allowPlainHTTP {
		t.Skip("c8s_dev builds allow plaintext for the integration harness")
	}
	dir := t.TempDir()
	k, _ := testKeyPEM(t)
	keyPath := writeKey(t, k)
	cert, err := issuer.SelfSignCA(k, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	body := testSnapshot(t, map[string]any{"format": cdsha.Format, "index": 5, "core": cdsha.Core{Policy: cdsha.FSMPolicy{Version: 1, LedgerTTLNS: int64(time.Hour), LedgerMax: 100, SecretsMaxPaths: 64, SecretsMaxPerHolder: 8, SecretsMaxValue: 4096}, ClusterID: "c1", Epoch: 1, RootCert: cert.Raw}, "key": keyDER})
	digests, err := cdsha.ContentDigests(body)
	if err != nil {
		t.Fatal(err)
	}
	pin := certutil.CertFingerprint(cert.Raw)
	b, err := cdsha.SealAuthenticatedBackup(&k.PublicKey, cdsha.BackupMeta{ClusterID: "c1", Epoch: 1, Index: 5, CAFingerprint: pin, StateDigest: digests.State}, body, cert.Raw, keyDER)
	if err != nil {
		t.Fatal(err)
	}
	kube := fake.NewClientset()
	if err := (cdsha.KubeDecrees{Client: kube, Namespace: "ns", ClusterID: "c1"}).PutBackup(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	list, _ := kube.CoreV1().ConfigMaps("ns").List(context.Background(), metav1.ListOptions{})
	raw, _ := json.Marshal(list)
	backup := filepath.Join(dir, "backup.json")
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	policy := func(name string, edit func(m map[string]any)) string {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(must(os.ReadFile("../../testdata/node-identities.json")), &doc); err != nil {
			t.Fatal(err)
		}
		for _, m := range doc["measurements"].([]any) {
			edit(m.(map[string]any))
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, must(json.Marshal(doc)), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	noAnchor := policy("no-anchor.json", func(m map[string]any) { delete(m, "approver_key") })
	noRTMRs := policy("no-rtmrs.json", func(m map[string]any) { delete(m, "rtmr") })
	st := cdsha.Status{ClusterID: "c1", NodeName: "n0", ID: "n0/1"}
	plain, plainHits := statusServer(t, st, false)
	tlsSrv, tlsHits := statusServer(t, st, true)
	mrtd := strings.Repeat("a1", 48)
	for name, args := range map[string][]string{
		"plaintext with --insecure": {"--url", plain.URL, "--insecure"},
		"launch digest only":        {"--url", tlsSrv.URL, "--measurements", mrtd},
		"policy without anchors":    {"--url", tlsSrv.URL, "--image-policy-file", noAnchor},
		"policy without RTMRs":      {"--url", tlsSrv.URL, "--image-policy-file", noRTMRs},
	} {
		cmd := newHARecoverCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"--cluster-id", "c1", "--bootstrap-node", "n0", "--backup-file", backup,
			"--recovery-key", keyPath, "--decree-key", keyPath, "--trusted-ca-sha256", pin,
			"--min-epoch", "0", "--min-index", "0", "--attempts", "1"}, args...))
		err := cmd.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "--image-policy-file") {
			t.Errorf("%s: %v, want a refusal that asks for --image-policy-file", name, err)
		}
	}
	if n := plainHits.Load() + tlsHits.Load(); n != 0 {
		t.Fatalf("weakly pinned endpoints answered %d requests", n)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
