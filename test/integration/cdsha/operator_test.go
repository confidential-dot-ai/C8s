//go:build integration

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// epochCA is the leader's epoch and CA fingerprint.
func (c *Cluster) epochCA() (uint64, string) {
	c.t.Helper()
	l := c.WaitLeader(30 * time.Second)
	st, _ := c.Status(l)
	return st.Epoch, st.CAFingerprint
}

// requireAllCA waits until every running replica serves CA fingerprint ca
// (or, with ca == "", any one fingerprint other than not).
func (c *Cluster) requireAllCA(ca, not string, timeout time.Duration) string {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		seen := map[string]bool{}
		ok := true
		for _, i := range c.RunningIDs() {
			st, good := c.Status(i)
			if !good || !st.Serving {
				ok = false
				break
			}
			seen[st.CAFingerprint] = true
		}
		if ok && len(seen) == 1 {
			for got := range seen {
				if (ca == "" || got == ca) && got != not {
					return got
				}
			}
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("replicas do not agree on the CA (want %.12s, not %.12s): %s", ca, not, c.StatusAll())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// requireFreshBackup: the stored backup reaches the leader's applied index
// as of now within a few backup intervals.
func requireFreshBackup(t *testing.T, c *Cluster) cdsha.Backup {
	t.Helper()
	l := c.WaitLeader(30 * time.Second)
	st, _ := c.Status(l)
	deadline := time.Now().Add(15 * time.Second)
	for {
		b, err := cdsha.BackupFromConfigMaps(clusterID, c.Backups())
		if err == nil && b.Meta.Index >= st.AppliedIndex && b.Meta.Epoch >= st.Epoch {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatalf("no backup at index >= %d (epoch %d) after 15s: %+v %v", st.AppliedIndex, st.Epoch, b.Meta, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestDecrees(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "D1-D2-bad-and-replayed-decrees", short: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			epoch, ca := c.epochCA()
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			exp := time.Now().Add(time.Hour)
			// D2: wrong key, another cluster, tampered body.
			wrong := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "wrong-key", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}, other)
			sd, _ := cdsha.SignDecree(cdsha.Decree{ClusterID: "other-cluster", IntentID: "other-cluster", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}, c.OpKey)
			cm, _ := cdsha.DecreeConfigMap(decreeNS, sd)
			cm.Labels[cdsha.LabelDecree] = clusterID // shown to this cluster
			c.PutConfigMap(cm)
			sd, _ = cdsha.SignDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "tampered", Kind: cdsha.UpdateMeasurements, BaseEpoch: epoch, Measurements: []string{measurement}, ExpiresAt: exp}, c.OpKey)
			sd.Decree.Measurements = []string{measurement, "m-evil"}
			tcm, _ := cdsha.DecreeConfigMap(decreeNS, sd)
			c.PutConfigMap(tcm)
			garbage := &corev1.ConfigMap{ObjectMeta: tcm.ObjectMeta, Data: map[string]string{"decree": "{not json"}}
			garbage.Name = cdsha.DecreeName(clusterID, "garbage")
			c.PutConfigMap(garbage)
			// D1: replay of the used Genesis (status removed) and a fresh
			// Genesis for a cluster that exists.
			replay := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "genesis", Kind: cdsha.Genesis, BootstrapNode: "n1", ExpiresAt: exp}, nil)
			second := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "genesis-2", Kind: cdsha.Genesis, BootstrapNode: "n2", ExpiresAt: exp}, nil)
			expired := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "expired", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: time.Now().Add(-time.Minute)}, nil)
			stale := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "stale-epoch", Kind: cdsha.RotateKey, BaseEpoch: epoch + 5, ExpiresAt: exp}, nil)
			for _, name := range []string{wrong, cm.Name, tcm.Name, garbage.Name, second, expired, stale} {
				st := c.WaitDecreeStatus(name, 20*time.Second)
				if st.AppliedEpoch != nil || st.RejectedReason == "" {
					t.Errorf("decree %s not rejected: %+v", name, st)
				}
				c.Logf("%s rejected: %s", name, st.RejectedReason)
			}
			if st := c.WaitDecreeStatus(replay, 20*time.Second); st.AppliedEpoch == nil || *st.AppliedEpoch != 1 {
				t.Errorf("replayed Genesis: %+v, want reported as applied at epoch 1 (and nothing done)", st)
			}
			if e, got := c.epochCA(); e != epoch || got != ca {
				t.Fatalf("bad decrees changed the cluster: epoch %d -> %d, CA %.12s -> %.12s", epoch, e, ca, got)
			}
			// A good RotateKey under load reaches every replica.
			good := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "rotate-1", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}, nil)
			if st := c.WaitDecreeStatus(good, 20*time.Second); st.AppliedEpoch == nil {
				t.Fatalf("RotateKey: %+v", st)
			}
			start := time.Now()
			c.requireAllCA("", ca, 20*time.Second)
			c.Logf("every replica has the rotated CA %s after the decree", time.Since(start))
			// Replay of the applied RotateKey: no second rotation.
			_, rotated := c.epochCA()
			c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "rotate-1", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}, nil)
			time.Sleep(3 * time.Second)
			if _, got := c.epochCA(); got != rotated {
				t.Fatal("a replayed RotateKey rotated again")
			}
		}},
		{name: "E1-rotate-key-during-partition", run: func(t *testing.T, c *Cluster, _ *Checker) {
			l := c.WaitLeader(10 * time.Second)
			f := followerVoter(t, c, l)
			c.Isolate(f)
			c.WaitNotServing(f, timing.lease+3*time.Second)
			epoch, ca := c.epochCA()
			name := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "rotate-p", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: time.Now().Add(time.Hour)}, nil)
			if st := c.WaitDecreeStatus(name, 20*time.Second); st.AppliedEpoch == nil {
				t.Fatalf("RotateKey during a partition: %+v", st)
			}
			// The isolated replica must not serve the old CA.
			if st, _ := c.Status(f); st.Serving {
				t.Errorf("isolated replica serving during the rotation: %s", c.StatusLine(f))
			}
			c.Heal()
			c.requireAllCA("", ca, 60*time.Second)
		}},
	})
}

// recoverAfterMajorityLoss: kill the leader and one more voter at once (with
// writes paused, so the survivor has every acked write), then a Recover
// decree naming the surviving voter.
func TestMajorityLoss(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "B4-two-voters-down-then-Recover", short: true, run: func(t *testing.T, c *Cluster, k *Checker) {
			l := c.WaitLeader(10 * time.Second)
			f := followerVoter(t, c, l)
			var survivor int
			for _, v := range c.Voters() {
				if v != l && v != f {
					survivor = v
				}
			}
			k.Pause()
			if _, _, err := k.Converge(30 * time.Second); err != nil {
				t.Fatal(err)
			}
			epoch, ca := c.epochCA()
			c.Kill(l)
			c.Kill(f)
			k.Resume()
			for _, i := range c.RunningIDs() {
				c.Logf("%s stopped serving after %s", c.Replicas[i].Node, c.WaitNotServing(i, timing.lease+5*time.Second))
			}
			hold(10 * time.Second) // fail closed: nobody serves, writes refused
			for _, i := range c.RunningIDs() {
				if st, _ := c.Status(i); st.Serving {
					t.Errorf("%s serving without a majority", c.Replicas[i].Node)
				}
			}
			name := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "recover-1", Kind: cdsha.Recover, BaseEpoch: epoch,
				BootstrapNode: c.Replicas[survivor].Node, ExpiresAt: time.Now().Add(10 * time.Minute)}, nil)
			start := time.Now()
			c.WaitServing([]int{survivor}, 60*time.Second)
			c.Logf("survivor %s serving %s after the Recover decree", c.Replicas[survivor].Node, time.Since(start))
			if st := c.WaitDecreeStatus(name, 30*time.Second); st.AppliedEpoch == nil {
				t.Errorf("Recover decree status: %+v", st)
			}
			c.WaitAllServing(60 * time.Second)
			c.Start(l, false)
			c.Start(f, false)
			c.WaitAllServing(60 * time.Second)
			c.WaitVoters(3, 60*time.Second)
			c.requireAllCA(ca, "", 30*time.Second)
			// D1: replay the used Recover decree: nothing happens.
			e2, _ := c.epochCA()
			c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "recover-1", Kind: cdsha.Recover, BaseEpoch: epoch,
				BootstrapNode: c.Replicas[survivor].Node, ExpiresAt: time.Now().Add(10 * time.Minute)}, nil)
			time.Sleep(3 * time.Second)
			if e3, _ := c.epochCA(); e3 != e2 {
				t.Errorf("replayed Recover changed the epoch %d -> %d", e2, e3)
			}
			// Spec D3: follow Recover with RotateKey.
			rot := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "rotate-after-recover", Kind: cdsha.RotateKey, BaseEpoch: e2, ExpiresAt: time.Now().Add(time.Hour)}, nil)
			if st := c.WaitDecreeStatus(rot, 20*time.Second); st.AppliedEpoch == nil {
				t.Fatalf("RotateKey after Recover: %+v", st)
			}
			c.requireAllCA("", ca, 30*time.Second)
		}},
		{name: "D5-recover-while-old-leader-alive", run: func(t *testing.T, c *Cluster, k *Checker) {
			// The operator wrongly names a replica that is only cut off,
			// while the majority still runs: the majority's leader refuses
			// the decree, and two clusters never serve at once.
			l := c.WaitLeader(10 * time.Second)
			epoch, _ := c.epochCA()
			c.Isolate(l)
			c.WaitNotServing(l, timing.lease+3*time.Second)
			nl := c.WaitLeader(20*time.Second, l)
			name := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "recover-wrong", Kind: cdsha.Recover, BaseEpoch: epoch,
				BootstrapNode: c.Replicas[l].Node, ExpiresAt: time.Now().Add(10 * time.Minute)}, nil)
			st := c.WaitDecreeStatus(name, 30*time.Second)
			c.Logf("Recover naming the isolated %s while %s leads: status %+v", c.Replicas[l].Node, c.Replicas[nl].Node, st)
			if st.AppliedEpoch != nil || !strings.Contains(st.RejectedReason, "majority") {
				t.Errorf("the majority leader did not refuse the Recover: %+v", st)
			}
			// Both sides serving at once = split brain.
			deadline := time.Now().Add(timing.deadAfter + 10*time.Second)
			for time.Now().Before(deadline) {
				a, _ := c.Status(l)
				b, _ := c.Status(nl)
				if a.Serving && b.Serving {
					t.Errorf("split brain: isolated %s serves (state %s, epoch %d) while %s serves (epoch %d)", c.Replicas[l].Node, a.State, a.Epoch, c.Replicas[nl].Node, b.Epoch)
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			c.Heal()
			c.WaitAllServing(60 * time.Second)
		}},
	})
}

// TestRestore: total loss and `c8s cds ha recover` from the sealed backup;
// an older backup than the operator's record is refused, and a live replica
// refuses any restore.
func TestRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
	c := NewCluster(t, clusterOpts{})
	c.WaitVoters(3, 30*time.Second)
	k := NewChecker(c, 4, 10*time.Millisecond)
	k.Start()
	time.Sleep(3 * time.Second)
	k.Pause()
	old := requireFreshBackup(t, c)
	oldList := c.Backups()
	k.Resume()
	time.Sleep(3 * time.Second)
	k.Pause()
	snaps, _, err := k.Converge(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	newest := requireFreshBackup(t, c)
	newList := c.Backups()
	c.Logf("old backup index %d, newest %d", old.Meta.Index, newest.Meta.Index)
	if newest.Meta.Index <= old.Meta.Index {
		t.Fatal("no newer backup")
	}
	write := func(name string, cms []corev1.ConfigMap) string {
		raw, _ := json.Marshal(corev1.ConfigMapList{Items: cms})
		p := filepath.Join(c.Dir, name)
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldFile, newFile := write("old.json", oldList), write("new.json", newList)
	recoverCLI := func(file string, node int, minEpoch, minIndex uint64, extra ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		args := append([]string{"cds", "ha", "recover", "--backup-file", file, "--recovery-key", c.RecKeyPath, "--decree-key", c.OpKeyPath,
			"--cluster-id", clusterID, "--bootstrap-node", c.Replicas[node].Node, "--url", c.Replicas[node].Base, "--insecure",
			"--min-epoch", strconv.FormatUint(minEpoch, 10), "--min-index", strconv.FormatUint(minIndex, 10)}, extra...)
		return c.RunCLI(ctx, args...)
	}
	// A live replica refuses a restore.
	if out, err := recoverCLI(newFile, 0, 1, 0, "--attempts", "1"); err == nil {
		t.Fatalf("a live replica took a restore: %s", out)
	} else {
		c.Logf("live replica refused the restore: %s", strings.TrimSpace(out))
	}
	k.Stop()
	// Total loss.
	for i := range c.Replicas {
		c.Kill(i)
	}
	for i := range c.Replicas {
		c.Start(i, false)
	}
	time.Sleep(timing.deadAfter + time.Second) // until they await a restore
	// D3: the old backup is refused against the operator's newer record.
	if out, err := recoverCLI(oldFile, 2, newest.Meta.Epoch, newest.Meta.Index); err == nil || !strings.Contains(out, "older than") {
		t.Fatalf("an older backup was restored: %v %s", err, out)
	}
	// D4: the wrong recovery key, a truncated part, another cluster's backup.
	wrongKey, wrongPath, _ := newKeyPair(t, c.Dir, "wrong-recovery")
	_ = wrongKey
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	out, err := c.RunCLI(ctx, "cds", "ha", "recover", "--backup-file", newFile, "--recovery-key", wrongPath, "--decree-key", c.OpKeyPath,
		"--cluster-id", clusterID, "--bootstrap-node", "n3", "--url", c.Replicas[2].Base, "--insecure", "--min-epoch", "1", "--min-index", "0")
	cancel()
	if err == nil {
		t.Fatalf("wrong recovery key opened the backup: %s", out)
	}
	truncated := make([]corev1.ConfigMap, len(newList))
	for i, cm := range newList {
		cm = *cm.DeepCopy()
		for key, v := range cm.BinaryData {
			cm.BinaryData[key] = v[:len(v)/2]
		}
		truncated[i] = cm
	}
	if out, err := recoverCLI(write("trunc.json", truncated), 2, 1, 0); err == nil {
		t.Fatalf("a truncated backup was restored: %s", out)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	out, err = c.RunCLI(ctx, "cds", "ha", "recover", "--backup-file", newFile, "--recovery-key", c.RecKeyPath, "--decree-key", c.OpKeyPath,
		"--cluster-id", "another", "--bootstrap-node", "n3", "--url", c.Replicas[2].Base, "--insecure", "--min-epoch", "1", "--min-index", "0")
	cancel()
	if err == nil {
		t.Fatalf("restored under another cluster id: %s", out)
	}
	start := time.Now()
	if out, err := recoverCLI(newFile, 2, newest.Meta.Epoch, newest.Meta.Index); err != nil {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	c.WaitAllServing(60 * time.Second)
	c.Logf("restored and every replica serving %s after recover", time.Since(start))
	k2 := NewChecker(c, 0, 0)
	got, _, err := k2.Converge(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var ref Snapshot
	for _, s := range snaps {
		ref = s
		break
	}
	for i, s := range got {
		if s.CA != ref.CA || s.ETag != ref.ETag || s.Secrets != ref.Secrets {
			t.Errorf("%s after restore differs from before the loss (CA %v, ETag %v, secrets %v)", c.Replicas[i].Node, s.CA == ref.CA, s.ETag == ref.ETag, s.Secrets == ref.Secrets)
		}
	}
}

// TestBigState: C3 (2,000 allowlist entries + 500 secrets, then a new member
// installs the snapshot; backup and restore sizes) and C4 (a secret of the
// maximum size through a follower).
func TestBigState(t *testing.T) {
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
	c := NewCluster(t, clusterOpts{})
	c.WaitVoters(3, 30*time.Second)
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan string, 100)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := w; n < 2500; n += 16 {
				var path string
				var body []byte
				if n < 2000 {
					path, body = fmt.Sprintf("/allowlist/workloads/big-%d", n), allowBody(fmt.Sprintf("big%d", n), n+1)
				} else {
					path = fmt.Sprintf("/secrets/big/%d", n)
					v := bytes.Repeat([]byte{byte(n)}, 1024)
					body, _ = json.Marshal(map[string]any{"value": base64.StdEncoding.EncodeToString(v)})
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				r := c.Do(ctx, n%len(c.Replicas), http.MethodPut, path, body, "op")
				cancel()
				if r.Err != nil || r.Code >= 300 {
					select {
					case errs <- fmt.Sprintf("%s: %d %v %s", path, r.Code, r.Err, r.Body):
					default:
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	c.Logf("2,000 entries + 500 secrets written in %s", time.Since(start))
	// C4: a secret of the maximum size (4096 bytes), through a non-voter.
	nv := c.NonVoterIDs()[0]
	big, _ := json.Marshal(map[string]any{"value": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 4096))})
	if r := c.Do(context.Background(), nv, http.MethodPut, "/secrets/big/max", big, "op"); r.Code != http.StatusCreated && r.Code != http.StatusOK {
		t.Fatalf("max-size secret through a non-voter: %d %s", r.Code, r.Body)
	}
	k := NewChecker(c, 0, 0)
	if _, d, err := k.Converge(60 * time.Second); err != nil {
		t.Fatal(err)
	} else {
		c.Logf("converged in %s", d)
	}
	b := requireFreshBackup(t, c)
	c.Logf("backup: index %d, %d bytes sealed, %d objects", b.Meta.Index, len(b.Ciphertext), len(c.Backups()))
	// A new member (restart with an empty store) installs the snapshot.
	c.Restart(nv, false)
	c.Logf("new member serving after %s", c.WaitServing([]int{nv}, 120*time.Second))
	if _, d, err := k.Converge(60 * time.Second); err != nil {
		t.Fatal(err)
	} else {
		c.Logf("new member converged %s later", d)
	}
}

// TestPeerPortGarbage: D7, junk on the peer port while the checker runs.
func TestPeerPortGarbage(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "D7-garbage-on-peer-port", short: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			targets := []string{}
			for _, r := range c.Replicas {
				targets = append(targets, net.JoinHostPort(r.Bind, strconv.Itoa(c.PeerPort)), net.JoinHostPort(r.Advertise, strconv.Itoa(c.PeerPort)))
			}
			var held []net.Conn
			defer func() {
				for _, h := range held {
					h.Close()
				}
			}()
			junk := make([]byte, 64<<10)
			_, _ = rand.Read(junk)
			end := time.Now().Add(20 * time.Second)
			if testing.Short() {
				end = time.Now().Add(8 * time.Second)
			}
			n := 0
			for time.Now().Before(end) {
				for _, a := range targets {
					n++
					conn, err := net.DialTimeout("tcp", a, time.Second)
					if err != nil {
						continue
					}
					switch n % 5 {
					case 0: // port scan: connect, close
						conn.Close()
					case 1: // random bytes
						_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
						_, _ = conn.Write(junk[:1+n%len(junk)])
						conn.Close()
					case 2: // a TLS client without attestation evidence
						tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the attacker
						_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
						_ = tc.Handshake()
						_, _ = tc.Write([]byte("R\x05hello"))
						tc.Close()
					case 3: // slowloris: hold the connection open, say nothing
						if len(held) < 200 {
							held = append(held, conn)
						} else {
							conn.Close()
						}
					case 4: // an HTTP request
						_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
						conn.Close()
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			c.Logf("%d hostile connections, %d held open", n, len(held))
			c.WaitAllServing(10 * time.Second)
		}},
	})
}
