package cds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Every replica lost: three fresh CDS processes wait; `c8s cds ha recover`
// opens the sealed backup the leader stored in the API server and restores
// it through the pre-join server; the new cluster serves the old mesh CA and
// allowlist.
func TestRunHARestoreAfterTotalLoss(t *testing.T) {
	c := newHATestCluster(t, []string{"127.0.4.10", "127.0.4.11", "127.0.4.12"})
	dir := t.TempDir()
	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	decreeKeyPath := writeFile("decree.key", c.decreeKeyPEM)
	rk, recPub := testKeyPEM(t)
	rkPEM, err := certutil.MarshalECKeyPEM(rk)
	if err != nil {
		t.Fatal(err)
	}
	recKeyPath := writeFile("recovery.key", rkPEM)
	timing := cdsha.DefaultTiming
	timing.Backup = 200 * time.Millisecond
	timing.DeadAfter = 2 * time.Second // /readyz waits for the dead replicas to be removed
	ha := c.haTemplate(timing)
	ha.recoveryKeyPEM = recPub

	errs, bases := c.start(ha)
	waitServing(t, bases, true)
	doc := []byte(anySeed(map[string]string{"web": digestA}))
	if code, body := c.firstWrite(bases[1], "/allowlist", doc); code != http.StatusNoContent {
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
	eventually(t, 45*time.Second, "a backup of the written state", func() bool {
		list, _ := c.kube.CoreV1().ConfigMaps("ns").List(context.Background(), metav1.ListOptions{LabelSelector: cdsha.LabelBackup + "=c1"})
		b, err := cdsha.BackupFromConfigMaps("c1", list.Items)
		backups = list.Items
		return err == nil && b.Meta.Index >= applied
	})
	// Signed now and spent only after the restore: spent tokens are part
	// of the replicated state, so only tokens from before Genesis are cut off.
	unspent := c.auth(http.MethodPut, "/allowlist", doc)
	c.stop(errs)

	// Total loss: fresh replicas, and the Genesis decree long since used.
	errs, bases = c.start(ha)
	t.Cleanup(func() { c.stop(errs) })
	waitServing(t, bases, false)
	// A replica that waits for a restore is ready, so the operator reaches
	// it through the Service.
	eventually(t, 40*time.Second, "a replica awaiting a restore is ready", func() bool {
		code, _, _ := do(t, http.MethodGet, bases[2]+"/readyz", "", nil)
		return code == http.StatusOK
	})
	raw, _ := json.Marshal(corev1.ConfigMapList{Items: backups})
	backupFile := filepath.Join(dir, "backup.json")
	_ = os.WriteFile(backupFile, raw, 0o600)
	// The custodians hold shares (3 of 5); the restore below runs from them,
	// through the CLI's own flag handling.
	shareDir := filepath.Join(dir, "shares")
	split := newHARecoveryKeyCmd()
	split.SetArgs([]string{"split", "--recovery-key", recKeyPath, "--out", shareDir, "--shares", "5", "--threshold", "3"})
	split.SetOut(io.Discard)
	if err := split.Execute(); err != nil {
		t.Fatal(err)
	}
	share := func(i int) []string {
		return []string{"--recovery-key-share", filepath.Join(shareDir, fmt.Sprintf("share-%d.json", i))}
	}
	keyArgs := append(append(share(1), share(3)...), share(5)...)
	run := func(key []string, extra ...string) (string, error) {
		cmd := newHARecoverCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		args := append([]string{"--backup-file", backupFile, "--decree-key", decreeKeyPath,
			"--cluster-id", "c1", "--url", bases[2], "--insecure"}, key...)
		cmd.SetArgs(append(args, extra...))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}
	recover := func(extra ...string) (string, error) { return run(keyArgs, extra...) }
	ok := []string{"--bootstrap-node", "n2", "--min-epoch", "1", "--min-index", "0", "--attempts", "2"}
	for name, key := range map[string][]string{
		"no key":                nil,
		"key and shares":        append([]string{"--recovery-key", recKeyPath}, share(1)...),
		"two shares of three":   append(share(2), share(4)...),
		"one share given twice": append(append(share(2), share(2)...), share(2)...),
	} {
		if out, err := run(key, ok...); err == nil {
			t.Fatalf("%s: restored: %q", name, out)
		}
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
	waitServing(t, bases, true)
	// A second recover over the serving cluster is refused: its new intent
	// is not in the decree record.
	if out, err := recover(ok...); err == nil {
		t.Fatalf("a second restore over a serving cluster succeeded: %q", out)
	}
	for _, b := range bases {
		_, h, _ := do(t, http.MethodGet, b+"/allowlist", "", nil)
		_, _, c := do(t, http.MethodGet, b+"/ca", "", nil)
		if h.Get("ETag") != h0.Get("ETag") || !bytes.Equal(c, ca) {
			t.Fatalf("%s after restore: etag %q want %q, same CA %v", b, h.Get("ETag"), h0.Get("ETag"), bytes.Equal(c, ca))
		}
	}
	if code, _, body := do(t, http.MethodPut, bases[0]+"/allowlist", unspent, doc); code != http.StatusNoContent {
		t.Fatalf("a token signed after Genesis, before the loss, refused after the restore: %d %s", code, body)
	}
}

// restoreApplied confirms a Restore from the decree record: a recover whose
// request timed out while the replica restored learns that it worked.
func TestRestoreAppliedReadsTheDecreeRecord(t *testing.T) {
	rec := []cdsha.DecreeRecord{{Decree: cdsha.SignedDecree{Decree: cdsha.Decree{Kind: cdsha.Restore, IntentID: "restore-1"}}},
		{Decree: cdsha.SignedDecree{Decree: cdsha.Decree{Kind: cdsha.UpdateMeasurements, IntentID: "restore-2"}}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ha/decrees" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(rec)
	}))
	defer srv.Close()
	ctx := context.Background()
	if !restoreApplied(ctx, srv.Client(), srv.URL, "restore-1") {
		t.Fatal("the recorded Restore was not found")
	}
	if restoreApplied(ctx, srv.Client(), srv.URL, "restore-2") || restoreApplied(ctx, srv.Client(), srv.URL, "restore-3") {
		t.Fatal("another decree kind or an unknown intent counted as the Restore")
	}
	if restoreApplied(ctx, srv.Client(), srv.URL+"/nowhere", "restore-1") {
		t.Fatal("an unreadable record counted as applied")
	}
}
