package cds

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// Every replica lost: three fresh CDS processes wait; `c8s cds ha recover`
// opens the sealed backup the leader stored in the API server and restores
// it through the pre-join server; the new cluster serves the old mesh CA and
// allowlist.
func TestRunHARestoreAfterTotalLoss(t *testing.T) {
	origKube, origAtt := newInClusterKubeClientset, newHAAttestor
	t.Cleanup(func() { newInClusterKubeClientset, newHAAttestor = origKube, origAtt })
	kube := fake.NewClientset()
	newInClusterKubeClientset = func() (kubernetes.Interface, error) { return kube, nil }
	newHAAttestor = func(string, cdsha.AttestorOptions) (cdsha.Attestor, error) { return fakeAttestor{"m1"}, nil }

	api := newHealthyAttestationApi(t)
	opKey, keysPath := writeOperatorKeyPair(t)
	dir := t.TempDir()
	writeKey := func(name string, k *ecdsa.PrivateKey) string {
		der, _ := x509.MarshalECPrivateKey(k)
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
		return p
	}
	decreeKeyPath := writeKey("decree.key", opKey)
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	recKeyPath := writeKey("recovery.key", rk)
	rpub, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	recPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rpub})

	httpPort, peerPort := freePort(t), freePort(t)
	hosts := []string{"127.0.4.10", "127.0.4.11", "127.0.4.12"}
	timing := cdsha.DefaultTiming
	timing.Backup = 200 * time.Millisecond

	sd, _ := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "genesis", Kind: cdsha.Genesis, BootstrapNode: "n0", ExpiresAt: time.Now().Add(time.Hour)}, opKey)
	cm, _ := cdsha.DecreeConfigMap("ns", sd)
	if _, err := kube.CoreV1().ConfigMaps("ns").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	start := func() (chan error, []string) {
		errs := make(chan error, len(hosts))
		bases := make([]string, len(hosts))
		for i, host := range hosts {
			cfg := validRunConfig(t, api.URL)
			cfg.host, cfg.port, cfg.operatorKeys, cfg.jwtClockSkew = host, httpPort, keysPath, 1
			cfg.logLevel = "info"
			var peers []string
			for j, h := range hosts {
				if j != i {
					peers = append(peers, fmt.Sprintf("%s:%d", h, peerPort))
				}
			}
			cfg.ha = haConfig{clusterID: "c1", decreeNS: "ns", peers: peers, advertiseIP: host, port: peerPort,
				nodeName: fmt.Sprintf("n%d", i), attestor: "test", pins: []string{"m1"}, operatorKey: keysPath,
				recoveryKeyPEM: recPub, seats: 3, maxNonVoters: 4, timing: timing}
			bases[i] = fmt.Sprintf("http://%s:%d", host, httpPort)
			go func() { errs <- run(cfg) }()
		}
		return errs, bases
	}
	stop := func(errs chan error) {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		for range hosts {
			select {
			case <-errs:
			case <-time.After(20 * time.Second):
				t.Fatal("a replica did not stop")
			}
		}
	}
	waitServing := func(bases []string, want bool) {
		deadline := time.Now().Add(30 * time.Second)
		for _, b := range bases {
			for {
				if time.Now().After(deadline) {
					t.Fatalf("%s: serving never became %v", b, want)
				}
				if resp, err := http.Get(b + "/ha/status"); err == nil {
					var st cdsha.Status
					_ = json.NewDecoder(resp.Body).Decode(&st)
					resp.Body.Close()
					full := true
					if want {
						// The pre-join server answers /ha/status too; wait
						// for the full one.
						c, _, _ := do(t, http.MethodGet, b+"/ca", "", nil)
						full = c == http.StatusOK
					}
					if st.Serving == want && (want || st.ID != "") && full {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	errs, bases := start()
	waitServing(bases, true)
	time.Sleep(2500 * time.Millisecond) // token cutoff after Genesis
	doc := []byte(anySeed(map[string]string{"web": digestA}))
	if code, _, body := do(t, http.MethodPut, bases[1]+"/allowlist", opToken(t, opKey, http.MethodPut, "/allowlist", doc), doc); code != http.StatusNoContent {
		t.Fatalf("write: %d %s", code, body)
	}
	_, h0, _ := do(t, http.MethodGet, bases[0]+"/allowlist", "", nil)
	var applied uint64
	for _, b := range bases {
		_, _, raw := do(t, http.MethodGet, b+"/ha/status", "", nil)
		var st cdsha.Status
		_ = json.Unmarshal(raw, &st)
		applied = max(applied, st.AppliedIndex)
	}
	_, _, ca := do(t, http.MethodGet, bases[0]+"/ca", "", nil)
	var backups []corev1.ConfigMap
	deadline := time.Now().Add(45 * time.Second)
	for {
		list, _ := kube.CoreV1().ConfigMaps("ns").List(context.Background(), metav1.ListOptions{LabelSelector: cdsha.LabelBackup + "=c1"})
		if b, err := cdsha.BackupFromConfigMaps("c1", list.Items); err == nil && b.Meta.Index >= applied {
			backups = list.Items
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no backup of the written state")
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop(errs)

	// Total loss: fresh replicas, and the Genesis decree long since used.
	errs, bases = start()
	t.Cleanup(func() { stop(errs) })
	waitServing(bases, false)
	raw, _ := json.Marshal(corev1.ConfigMapList{Items: backups})
	backupFile := filepath.Join(dir, "backup.json")
	_ = os.WriteFile(backupFile, raw, 0o600)
	recover := func(extra ...string) (string, error) {
		cmd := newHARecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append([]string{"--backup-file", backupFile, "--recovery-key", recKeyPath, "--decree-key", decreeKeyPath,
			"--cluster-id", "c1", "--url", bases[2], "--insecure"}, extra...))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	if _, err := recover("--bootstrap-node", "n2"); err == nil {
		t.Fatal("recover without --min-epoch/--min-index")
	}
	if out, err := recover("--bootstrap-node", "n2", "--min-epoch", "9", "--min-index", "0"); err == nil || !strings.Contains(out, "backup:") {
		t.Fatalf("an older backup than the operator accepts was restored: %v %q", err, out)
	}
	if out, err := recover("--bootstrap-node", "n0", "--min-epoch", "1", "--min-index", "0", "--attempts", "2"); err == nil {
		t.Fatalf("a replica restored a decree naming another node: %q", out)
	}
	if out, err := recover("--bootstrap-node", "n2", "--min-epoch", "1", "--min-index", "0"); err != nil {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	waitServing(bases, true)
	for _, b := range bases {
		_, h, _ := do(t, http.MethodGet, b+"/allowlist", "", nil)
		_, _, c := do(t, http.MethodGet, b+"/ca", "", nil)
		if h.Get("ETag") != h0.Get("ETag") || !bytes.Equal(c, ca) {
			t.Fatalf("%s after restore: etag %q want %q, same CA %v", b, h.Get("ETag"), h0.Get("ETag"), bytes.Equal(c, ca))
		}
	}
}
