//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
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
func (c *Cluster) requireAllCA(ca, not string, timeout time.Duration) {
	c.t.Helper()
	c.waitFor(timeout, func() bool {
		seen := map[string]bool{}
		for _, i := range c.RunningIDs() {
			st, ok := c.Status(i)
			if !ok || !st.Serving {
				return false
			}
			seen[st.CAFingerprint] = true
		}
		return len(seen) == 1 && !seen[not] && (ca == "" || seen[ca])
	}, func() string {
		return fmt.Sprintf("replicas do not agree on the CA (want %.12s, not %.12s):%s", ca, not, c.StatusAll())
	})
}

// requireFreshBackup: the stored backup reaches the leader's applied index
// as of now within a few backup intervals.
func requireFreshBackup(t *testing.T, c *Cluster) cdsha.Backup {
	t.Helper()
	l := c.WaitLeader(30 * time.Second)
	st, _ := c.Status(l)
	var b cdsha.Backup
	var err error
	c.waitFor(15*time.Second, func() bool {
		b, err = cdsha.BackupFromConfigMaps(clusterID, c.Backups())
		return err == nil && b.Meta.Index >= st.AppliedIndex && b.Meta.Epoch >= st.Epoch
	}, func() string {
		return fmt.Sprintf("no backup at index >= %d (epoch %d): %+v %v", st.AppliedIndex, st.Epoch, b.Meta, err)
	})
	return b
}

func TestDecrees(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "D1-D2-bad-and-replayed-decrees", short: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			// The checks themselves are TestCheckDecree's; this row proves the
			// leader writes a status for each decree, survives garbage, and
			// treats replays as no-ops.
			epoch, ca := c.epochCA()
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			exp := time.Now().Add(time.Hour)
			// D2: wrong key, and an object that is not JSON.
			wrong := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "wrong-key", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}, other)
			sd, _ := cdsha.SignDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "garbage", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}, c.OpKey)
			garbage, _ := cdsha.DecreeConfigMap(decreeNS, sd)
			garbage.Data = map[string]string{"decree": "{not json"}
			c.PutConfigMap(garbage)
			// D1: replay of the used Genesis (status removed).
			replay := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "genesis", Kind: cdsha.Genesis, BootstrapNode: "n1", ExpiresAt: exp}, nil)
			for _, name := range []string{wrong, garbage.Name} {
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
			rotate := cdsha.Decree{ClusterID: clusterID, IntentID: "rotate-1", Kind: cdsha.RotateKey, BaseEpoch: epoch, ExpiresAt: exp}
			good := c.PutDecree(rotate, nil)
			applied := c.WaitDecreeStatus(good, 20*time.Second)
			if applied.AppliedEpoch == nil {
				t.Fatalf("RotateKey: %+v", applied)
			}
			start := time.Now()
			c.requireAllCA("", ca, 20*time.Second)
			c.Logf("every replica has the rotated CA %s after the decree", time.Since(start))
			// Replay of the applied RotateKey: reported as applied at the
			// same epoch, no second rotation. Rewriting the object drops
			// its status, so a new status means the leader has read it.
			_, rotated := c.epochCA()
			if st := c.WaitDecreeStatus(c.PutDecree(rotate, nil), 20*time.Second); st.AppliedEpoch == nil || *st.AppliedEpoch != *applied.AppliedEpoch {
				t.Errorf("replayed RotateKey: %+v, want applied at epoch %d", st, *applied.AppliedEpoch)
			}
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
			// The isolated replica must not serve the old CA, for at least
			// a lease after the rotation.
			c.never(timing.lease, func() string {
				if st, _ := c.Status(f); st.Serving {
					return "isolated replica serving during the rotation: " + c.StatusLine(f)
				}
				return ""
			})
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
			if _, _, err := c.Converge(30 * time.Second); err != nil {
				t.Fatal(err)
			}
			epoch, ca := c.epochCA()
			c.Kill(l)
			c.Kill(f)
			k.Resume()
			for _, i := range c.RunningIDs() {
				c.Logf("%s stopped serving after %s", c.Replicas[i].Node, c.WaitNotServing(i, timing.lease+5*time.Second))
			}
			// Fail closed: nobody serves, writes are refused.
			c.never(scaled(10*time.Second), func() string {
				for _, i := range c.RunningIDs() {
					if st, _ := c.Status(i); st.Serving {
						return c.Replicas[i].Node + " serving without a majority"
					}
				}
				return ""
			})
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
			c.never(timing.deadAfter+10*time.Second, func() string {
				a, _ := c.Status(l)
				b, _ := c.Status(nl)
				if a.Serving && b.Serving {
					return fmt.Sprintf("split brain: isolated %s serves (state %s, epoch %d) while %s serves (epoch %d)", c.Replicas[l].Node, a.State, a.Epoch, c.Replicas[nl].Node, b.Epoch)
				}
				return ""
			})
			c.Heal()
			c.WaitAllServing(60 * time.Second)
		}},
	})
}

// TestRestore: total loss and `c8s cds ha recover` from the sealed backup.
// Refusals (older backup, live replica, wrong keys, tampered parts, other
// clusters) are unit tests (backup_test.go, ha_restore_test.go).
func TestRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
	c := NewCluster(t)
	c.WaitVoters(3, 30*time.Second)
	k := NewChecker(c, 4, 10*time.Millisecond)
	k.Start()
	time.Sleep(3 * time.Second)
	k.Pause()
	snaps, _, err := c.Converge(30 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Retain trust from the live cluster, before exporting backups or losing
	// every member. The local harness uses trusted loopback plus operator auth;
	// production operators must authenticate the server with armTLS.
	leader := c.WaitLeader(30 * time.Second)
	pinResponse := c.Do(context.Background(), leader, http.MethodGet, "/ha/status", nil, true)
	var trusted cdsha.Status
	if pinResponse.Err != nil || pinResponse.Code != http.StatusOK || json.Unmarshal(pinResponse.Body, &trusted) != nil {
		t.Fatalf("authenticated pre-loss status: %d %v %s", pinResponse.Code, pinResponse.Err, pinResponse.Body)
	}
	pin, err := hex.DecodeString(trusted.CAFingerprint)
	if err != nil || len(pin) != 32 || len(trusted.CAFingerprint) != 64 || !trusted.Serving || trusted.ClusterID != clusterID {
		t.Fatalf("invalid pre-loss recovery identity: %+v", trusted)
	}
	newest := requireFreshBackup(t, c)
	raw, _ := json.Marshal(corev1.ConfigMapList{Items: c.Backups()})
	newFile := filepath.Join(c.Dir, "backup.json")
	if err := os.WriteFile(newFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	k.Stop()
	// Total loss.
	for i := range c.Replicas {
		c.Kill(i)
	}
	for i := range c.Replicas {
		c.Start(i, false)
	}
	// The pre-join server is ready once the replica awaits a restore.
	c.waitFor(timing.deadAfter+30*time.Second, func() bool { return c.Get(2, "/readyz").Code == http.StatusOK },
		func() string { return "n3 does not await a restore: " + c.StatusLine(2) })
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "cds", "ha", "recover", "--backup-file", newFile,
		"--recovery-key", c.RecKeyPath, "--decree-key", c.OpKeyPath, "--cluster-id", clusterID,
		"--trusted-ca-sha256", trusted.CAFingerprint,
		"--bootstrap-node", c.Replicas[2].Node, "--url", c.Replicas[2].Base, "--insecure",
		"--min-epoch", strconv.FormatUint(newest.Meta.Epoch, 10), "--min-index", strconv.FormatUint(newest.Meta.Index, 10)).CombinedOutput()
	if err != nil {
		t.Fatalf("recover: %v\n%s", err, out)
	}
	c.WaitAllServing(60 * time.Second)
	c.Logf("restored and every replica serving %s after recover", time.Since(start))
	got, _, err := c.Converge(30 * time.Second)
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

// TestBigState: C3 (2,000 allowlist entries + 500 secrets, then a restarted
// non-voter installs the snapshot) and C4 (a max-size secret through a
// non-voter).
func TestBigState(t *testing.T) {
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
	// This tests live state size, not unbounded quadratic document history.
	// Keep the existing production pruning and store guard enabled. The hard
	// snapshot capacity contract needs separate admission tests; these knobs
	// alone do not prove admission safety for arbitrary workloads.
	c := newClusterWithRaftTiming(t, timing.heartbeat, timing.election,
		"--allowlist-history-bytes", "64Mi", "--allowlist-max-bytes", "256Mi")
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
				r := c.Do(ctx, n%len(c.Replicas), http.MethodPut, path, body, true)
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
	if r := c.Do(context.Background(), nv, http.MethodPut, "/secrets/big/max", big, true); r.Code != http.StatusCreated && r.Code != http.StatusOK {
		t.Fatalf("max-size secret through a non-voter: %d %s", r.Code, r.Body)
	}
	if _, d, err := c.Converge(60 * time.Second); err != nil {
		t.Fatal(err)
	} else {
		c.Logf("converged in %s", d)
	}
	b := requireFreshBackup(t, c)
	c.Logf("backup: index %d, %d objects", b.Meta.Index, len(c.Backups()))
	// A new member (restart with an empty store) installs the snapshot.
	c.Restart(nv, false)
	c.Logf("new member serving after %s", c.WaitServing([]int{nv}, 120*time.Second))
	if _, d, err := c.Converge(60 * time.Second); err != nil {
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
