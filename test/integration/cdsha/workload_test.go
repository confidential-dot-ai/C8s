//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// historyBound keeps the whole-document allowlist history from growing
// without bound on the shared tmpfs (as TestBigState does): these rows test
// live state size and shape, not unbounded history.
var historyBound = []string{"--allowlist-history-bytes", "64Mi", "--allowlist-max-bytes", "256Mi"}

// auxOp is one write of a scenario's own workload.
type auxOp struct {
	Op
	Method string
	Start  time.Time
	Node   int
}

// auxDo sends one operator write to replica i and files it with the checker.
func auxDo(c *Cluster, k *Checker, i int, method, path string, body []byte, kind, key string, seq int) auxOp {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	op := auxOp{Op: Op{Kind: kind, Key: key, Seq: seq}, Method: method, Start: time.Now(), Node: i}
	r := c.Do(ctx, i, method, path, body, true)
	op.End, op.Code = time.Now(), r.Code
	if r.Err != nil {
		op.Err = r.Err.Error()
	}
	op.Body = strings.TrimSpace(string(r.Body))
	if len(op.Body) > 300 {
		op.Body = op.Body[:300]
	}
	k.recordAux(i, method, path, r.Code, op.Body)
	return op
}

// randomRunning is a random running replica, or -1.
func randomRunning(c *Cluster) int {
	ids := c.RunningIDs()
	if len(ids) == 0 {
		return -1
	}
	return ids[rand.IntN(len(ids))]
}

// parseAllowPrefix is workload name (minus prefix) -> digest number for
// allowlist entries named prefix*.
func parseAllowPrefix(body []byte, prefix string) (map[string]int, error) {
	var doc struct {
		Workloads map[string]struct {
			Containers []struct {
				Digest string `json:"digest"`
			} `json:"containers"`
		} `json:"workloads"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for name, wl := range doc.Workloads {
		key, ok := strings.CutPrefix(name, prefix)
		if !ok || len(wl.Containers) == 0 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimPrefix(wl.Containers[0].Digest, "sha256:"), 16, 64)
		if err != nil {
			out[key] = -1
			continue
		}
		out[key] = int(v)
	}
	return out, nil
}

// secretsPrefix is path (minus "/"+prefix) -> raw value for secrets under prefix.
func secretsPrefix(body []byte, prefix string) (map[string]string, error) {
	var ents []struct {
		Path  string `json:"path"`
		Value []byte `json:"value"`
	}
	if err := json.Unmarshal(body, &ents); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range ents {
		if key, ok := strings.CutPrefix(strings.TrimPrefix(e.Path, "/"), prefix); ok {
			out[key] = string(e.Value)
		}
	}
	return out, nil
}

// readBoth reads replica i's allowlist and secret dump (200 only).
func readBoth(c *Cluster, i int) (allow, secrets []byte, ok bool) {
	a := c.Get(i, "/allowlist")
	s := c.Get(i, "/dev/ha/secrets")
	if a.Err != nil || s.Err != nil || a.Code != http.StatusOK || s.Code != http.StatusOK {
		return nil, nil, false
	}
	return a.Body, s.Body, true
}

func secretBody(value string) []byte {
	b, _ := json.Marshal(map[string]any{"value": base64.StdEncoding.EncodeToString([]byte(value)), "overwrite": true})
	return b
}

// converged heals, waits for every replica to serve and agree, and returns
// one replica's (allowlist, secrets) bodies per running replica.
func converged(t *testing.T, c *Cluster) map[int][2][]byte {
	t.Helper()
	c.Heal()
	c.WaitAllServing(60 * time.Second)
	if _, _, err := c.Converge(90 * time.Second); err != nil {
		t.Fatalf("converge: %v", err)
	}
	out := map[int][2][]byte{}
	for _, i := range c.RunningIDs() {
		a, s, ok := readBoth(c, i)
		if !ok {
			t.Fatalf("%s: read after convergence failed", c.Replicas[i].Node)
		}
		out[i] = [2][]byte{a, s}
	}
	return out
}

func showErr(t *testing.T, what string, xs []string) {
	t.Helper()
	if len(xs) == 0 {
		return
	}
	if len(xs) > 10 {
		xs = append(xs[:10:10], fmt.Sprintf("... and %d more", len(xs)-10))
	}
	t.Errorf("%s:\n  %s", what, strings.Join(xs, "\n  "))
}

// --- W1: hot key -------------------------------------------------------------

// hotKeyCheck: the final value v of one register written concurrently must
// be one some write may have applied (acked or indeterminate), and must not
// be a write that was acknowledged before another acknowledged write began
// (that later write must have replaced it). Indeterminate writes may apply
// late, so they never count as completed.
func hotKeyCheck(ops []auxOp, final int, present bool) (string, int) {
	var vOp *auxOp
	for n := range ops {
		if ops[n].Seq == final && !ops[n].Definite() {
			vOp = &ops[n]
		}
	}
	if !present {
		for _, o := range ops {
			if o.Acked() {
				return fmt.Sprintf("value absent though write %d was acked", o.Seq), 0
			}
		}
		return "", 0
	}
	if vOp == nil {
		return fmt.Sprintf("final value %d was never possibly written", final), 0
	}
	newer := 0
	for _, o := range ops {
		if o.Acked() && vOp.Acked() && vOp.End.Before(o.Start) {
			newer++
		}
	}
	if newer > 0 {
		return fmt.Sprintf("final value %d (acked at %s) is older than %d acked writes that began after it", final, vOp.End.Format("15:04:05.000"), newer), newer
	}
	return "", 0
}

func hotKey(t *testing.T, c *Cluster, k *Checker) {
	var seq atomic.Int64
	var mu sync.Mutex
	var allowOps, secretOps []auxOp
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				i := randomRunning(c)
				if i < 0 {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				s := int(seq.Add(1))
				var op auxOp
				if w%2 == 0 {
					op = auxDo(c, k, i, http.MethodPut, "/allowlist/workloads/hk-hot", allowBody("hk", s), "allow", "hot", s)
				} else {
					op = auxDo(c, k, i, http.MethodPut, "/secrets/hk/hot", secretBody("hot:"+strconv.Itoa(s)), "secret", "hot", s)
				}
				mu.Lock()
				if w%2 == 0 {
					allowOps = append(allowOps, op)
				} else {
					secretOps = append(secretOps, op)
				}
				mu.Unlock()
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	hold(20 * time.Second)
	l := c.WaitLeader(10 * time.Second)
	c.Kill(l)
	c.WaitLeader(30*time.Second, l)
	c.Start(l, false)
	hold(20 * time.Second)
	close(stop)
	wg.Wait()
	snaps := converged(t, c)
	for _, kind := range []string{"allow", "secret"} {
		ops := allowOps
		if kind == "secret" {
			ops = secretOps
		}
		acked, indet := 0, 0
		for _, o := range ops {
			if o.Acked() {
				acked++
			} else if !o.Definite() {
				indet++
			}
		}
		for i, s := range snaps {
			var final int
			var present bool
			if kind == "allow" {
				m, err := parseAllowPrefix(s[0], "hk-")
				if err != nil {
					t.Fatal(err)
				}
				final, present = m["hot"]
			} else {
				m, err := secretsPrefix(s[1], "hk/")
				if err != nil {
					t.Fatal(err)
				}
				var v string
				v, present = m["hot"]
				if present {
					n, err := strconv.Atoi(strings.TrimPrefix(v, "hot:"))
					if err != nil {
						t.Errorf("%s: hot secret value %q", c.Replicas[i].Node, v)
					}
					final = n
				}
			}
			if msg, _ := hotKeyCheck(ops, final, present); msg != "" {
				t.Errorf("hot key %s at %s: %s", kind, c.Replicas[i].Node, msg)
			} else if i == c.RunningIDs()[0] {
				c.Logf("hot key %s: %d writes, %d acked, %d indeterminate; final %d", kind, len(ops), acked, indet, final)
			}
		}
		if acked == 0 {
			t.Errorf("hot key %s: no write acked", kind)
		}
	}
}

// --- W2: large bodies -----------------------------------------------------------

// bigAllowBody is a workload document of about size bytes: n containers with
// distinct digests (the first carries seq).
func bigAllowBody(name string, seq, size int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"label":"ghcr.io/it/%s:v1","containers":[`, name)
	for n := 0; b.Len() < size-200; n++ {
		if n > 0 {
			b.WriteByte(',')
		}
		d := fmt.Sprintf("%064x", seq)
		if n > 0 {
			d = fmt.Sprintf("%08x%056x", 0xb16b0000+seq, n)
		}
		fmt.Fprintf(&b, `{"digest":"sha256:%s","command":{"policy":"any"},"args":{"policy":"any"}}`, d)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

func largeBodies(t *testing.T, c *Cluster, k *Checker) {
	const cap = 1 << 20 // allowlistWriteBodyCap (routes.go)
	const maxValue = 4096 // --secrets-max-value-bytes default (cmd.go)
	nv := c.NonVoterIDs()[0]
	l := c.WaitLeader(10 * time.Second)
	check := func(what string, op auxOp, want func(int) bool) {
		c.Logf("%s via %s: %d %q", what, c.Replicas[op.Node].Node, op.Code, op.Body)
		if op.Err != "" || !want(op.Code) {
			t.Errorf("%s: code %d err %q body %q", what, op.Code, op.Err, op.Body)
		}
	}
	ok2xx := func(code int) bool { return code >= 200 && code < 300 }
	is4xx := func(code int) bool { return code >= 400 && code < 500 }
	// Secrets: exactly the max value, one byte over, a body over the cap.
	exact := strings.Repeat("v", maxValue)
	check("secret value of exactly 4096 bytes", auxDo(c, k, nv, http.MethodPut, "/secrets/lb/exact", secretBody(exact), "secret", "exact", 1), ok2xx)
	check("secret value of 4097 bytes", auxDo(c, k, l, http.MethodPut, "/secrets/lb/over", secretBody(exact+"v"), "secret", "over", 1), is4xx)
	hugeSecret := secretBody(strings.Repeat("v", cap))
	check(fmt.Sprintf("secret PUT body %d bytes (> cap)", len(hugeSecret)), auxDo(c, k, nv, http.MethodPut, "/secrets/lb/huge", hugeSecret, "secret", "huge", 1),
		func(code int) bool { return code == http.StatusRequestEntityTooLarge })
	// Allowlist documents: the largest under the cap, through the leader
	// and a non-voter, then one over the cap.
	accepted := map[string]int{}
	for n, target := range []int{256 << 10, 768 << 10, cap - 2048, cap - 64} {
		via := []int{l, nv}[n%2]
		name := fmt.Sprintf("lb%d", n)
		body := bigAllowBody(name, 1000+n, target)
		if len(body) > cap {
			body = bigAllowBody(name, 1000+n, target-(len(body)-cap)-1)
		}
		op := auxDo(c, k, via, http.MethodPut, "/allowlist/workloads/lb-"+name, body, "allow", name, 1000+n)
		c.Logf("allowlist document of %d bytes via %s: %d %q (%s)", len(body), c.Replicas[via].Node, op.Code, op.Body, op.End.Sub(op.Start).Round(time.Millisecond))
		switch {
		case op.Acked():
			accepted[name] = 1000 + n
		case op.Err != "" || op.Code >= 500:
			t.Errorf("allowlist document of %d bytes: code %d err %q body %q", len(body), op.Code, op.Err, op.Body)
		}
	}
	over := bigAllowBody("lbover", 2000, cap+4096)
	check(fmt.Sprintf("allowlist document %d bytes (> cap)", len(over)), auxDo(c, k, l, http.MethodPut, "/allowlist/workloads/lb-over", over, "allow", "over", 2000),
		func(code int) bool { return code == http.StatusRequestEntityTooLarge })
	if len(accepted) == 0 {
		t.Error("no large allowlist document accepted")
	}
	verify := func(when string) {
		snaps := converged(t, c)
		for i, s := range snaps {
			m, _ := parseAllowPrefix(s[0], "lb-")
			for name, want := range accepted {
				if m[name] != want {
					t.Errorf("%s %s: lb-%s = %d, want %d", when, c.Replicas[i].Node, name, m[name], want)
				}
			}
			if _, bad := m["over"]; bad {
				t.Errorf("%s %s: the refused oversized document is present", when, c.Replicas[i].Node)
			}
			sec, _ := secretsPrefix(s[1], "lb/")
			if sec["exact"] != exact {
				t.Errorf("%s %s: 4096-byte secret len %d", when, c.Replicas[i].Node, len(sec["exact"]))
			}
			for _, bad := range []string{"over", "huge"} {
				if _, ok := sec[bad]; ok {
					t.Errorf("%s %s: refused secret %s present", when, c.Replicas[i].Node, bad)
				}
			}
		}
		c.Logf("%s: %d large documents identical on %d replicas", when, len(accepted), len(snaps))
	}
	verify("after writes")
	for _, i := range c.RunningIDs() {
		if !c.Running(i) {
			t.Errorf("%s exited", c.Replicas[i].Node)
		}
	}
	// A fresh member installs a snapshot holding the large documents.
	c.Restart(nv, false)
	c.Logf("fresh %s serving after %s", c.Replicas[nv].Node, c.WaitServing([]int{nv}, 120*time.Second))
	verify("after snapshot install")
	// Remove them, so the rest of the run is not on a multi-MiB document.
	for name := range accepted {
		op := auxDo(c, k, c.WaitLeader(10*time.Second), http.MethodDelete, "/allowlist/workloads/lb-"+name, nil, "allow", name, 0)
		if !op.Acked() {
			t.Errorf("delete lb-%s: %d %q %q", name, op.Code, op.Err, op.Body)
		}
	}
}

// --- W3: wide keyspace ---------------------------------------------------------

func wideKeyspace(t *testing.T, c *Cluster, k *Checker) {
	const nAllow, nSecret = 3500, 1600
	type res struct {
		acked, tried bool
	}
	results := make([]res, nAllow+nSecret)
	var next atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	var definiteRetries atomic.Int64
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := int(next.Add(1)) - 1
				if n >= len(results) {
					return
				}
				for attempt := 0; attempt < 20; attempt++ {
					i := randomRunning(c)
					var op auxOp
					if n < nAllow {
						op = auxDo(c, k, i, http.MethodPut, fmt.Sprintf("/allowlist/workloads/wk-%d", n), allowBody(fmt.Sprintf("wk%d", n), 0x7000000+n), "allow", strconv.Itoa(n), n)
					} else {
						op = auxDo(c, k, i, http.MethodPut, fmt.Sprintf("/secrets/wk/%d", n), secretBody(fmt.Sprintf("wk:%d", n)), "secret", strconv.Itoa(n), n)
					}
					if !op.Definite() {
						results[n] = res{acked: op.Acked(), tried: true}
						break
					}
					// Refused before it took effect: safe to retry.
					definiteRetries.Add(1)
					time.Sleep(200 * time.Millisecond)
				}
			}
		}()
	}
	// Halfway, a fresh non-voter joins (snapshot install while writing).
	time.Sleep(10 * time.Second)
	nv := c.NonVoterIDs()[0]
	c.Restart(nv, false)
	wg.Wait()
	acked := 0
	for _, r := range results {
		if r.acked {
			acked++
		}
	}
	c.Logf("%d keys written in %s: %d acked, %d definite refusals retried", len(results), time.Since(start).Round(time.Millisecond), acked, definiteRetries.Load())
	c.WaitAllServing(120 * time.Second)
	c.WaitVoters(seats, 60*time.Second)
	// Restart a follower voter and a non-voter with empty stores: both must
	// install the snapshot (5k+ entries, far past SnapshotThreshold 512).
	l := c.WaitLeader(10 * time.Second)
	f := followerVoter(t, c, l)
	c.Restart(f, false)
	c.Restart(c.NonVoterIDs()[0], false)
	c.Logf("restarted members serving after %s", c.WaitAllServing(120*time.Second))
	c.WaitVoters(seats, 60*time.Second)
	snaps := converged(t, c)
	for i, s := range snaps {
		al, err := parseAllowPrefix(s[0], "wk-")
		if err != nil {
			t.Fatal(err)
		}
		sec, err := secretsPrefix(s[1], "wk/")
		if err != nil {
			t.Fatal(err)
		}
		var lost, invented []string
		for n, r := range results {
			key := strconv.Itoa(n)
			var present, right bool
			if n < nAllow {
				v, ok := al[key]
				present, right = ok, v == 0x7000000+n
			} else {
				v, ok := sec[key]
				present, right = ok, v == fmt.Sprintf("wk:%d", n)
			}
			if r.acked && (!present || !right) {
				lost = append(lost, fmt.Sprintf("key %d present %v right %v", n, present, right))
			}
			if present && (!r.tried || !right) {
				invented = append(invented, fmt.Sprintf("key %d tried %v right %v", n, r.tried, right))
			}
		}
		for key := range al {
			if n, err := strconv.Atoi(key); err != nil || n < 0 || n >= nAllow {
				invented = append(invented, "allow wk-"+key)
			}
		}
		for key := range sec {
			if n, err := strconv.Atoi(key); err != nil || n < nAllow || n >= len(results) {
				invented = append(invented, "secret wk/"+key)
			}
		}
		showErr(t, c.Replicas[i].Node+": acked wide-keyspace writes lost", lost)
		showErr(t, c.Replicas[i].Node+": wide-keyspace values nobody wrote", invented)
		c.Logf("%s: %d allowlist + %d secret wide keys present", c.Replicas[i].Node, len(al), len(sec))
	}
}

// --- W4: delete / overwrite mix ------------------------------------------------

// dmState is a key's state: absent (-1) or present with seq.
type dmKey struct {
	name     string
	state    int  // after the last acked op; -1 absent
	abandon  bool // last op indeterminate
	alt      int  // the state that op would leave
	touched  bool
}

func deleteMix(t *testing.T, c *Cluster, k *Checker) {
	const writers, slots = 4, 8
	var mu sync.Mutex
	var keys []*dmKey
	var del404 []string
	var nPut, nDel, nIndet atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cur := make([]*dmKey, slots)
			gen := make([]int, slots)
			newKey := func(j int) *dmKey {
				dk := &dmKey{name: fmt.Sprintf("dm-w%ds%dg%d", w, j, gen[j]), state: -1}
				mu.Lock()
				keys = append(keys, dk)
				mu.Unlock()
				return dk
			}
			for j := range cur {
				cur[j] = newKey(j)
			}
			seq := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				j := rand.IntN(slots)
				dk := cur[j]
				i := randomRunning(c)
				if i < 0 {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				seq++
				var op auxOp
				del := dk.state >= 0 && rand.IntN(2) == 0
				if del {
					nDel.Add(1)
					op = auxDo(c, k, i, http.MethodDelete, "/allowlist/workloads/"+dk.name, nil, "allow", dk.name, -1)
				} else {
					nPut.Add(1)
					op = auxDo(c, k, i, http.MethodPut, "/allowlist/workloads/"+dk.name, allowBody(dk.name, 0x5000000+seq), "allow", dk.name, 0x5000000+seq)
				}
				effect := -1
				if !del {
					effect = 0x5000000 + seq
				}
				mu.Lock()
				dk.touched = true
				switch {
				case op.Acked():
					dk.state = effect
				case del && op.Code == http.StatusNotFound:
					// The key was present per the last acked write.
					del404 = append(del404, fmt.Sprintf("%s DELETE %s at %s: 404 though last acked state is %d", op.End.Format("15:04:05.000"), dk.name, c.Replicas[i].Node, dk.state))
				case op.Definite():
				default:
					dk.abandon, dk.alt = true, effect
					nIndet.Add(1)
				}
				mu.Unlock()
				if dk.abandon {
					gen[j]++
					cur[j] = newKey(j)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	hold(20 * time.Second)
	l := c.WaitLeader(10 * time.Second)
	c.Kill(l)
	c.WaitLeader(30*time.Second, l)
	c.Start(l, true)
	hold(20 * time.Second)
	close(stop)
	wg.Wait()
	snaps := converged(t, c)
	for i, s := range snaps {
		m, err := parseAllowPrefix(s[0], "")
		if err != nil {
			t.Fatal(err)
		}
		var bad []string
		known := map[string]bool{}
		for _, dk := range keys {
			known[dk.name] = true
			got, present := m[dk.name]
			if !present {
				got = -1
			}
			okState := got == dk.state || (dk.abandon && got == dk.alt)
			if !okState {
				bad = append(bad, fmt.Sprintf("%s = %d, want %d (abandoned %v, alt %d)", dk.name, got, dk.state, dk.abandon, dk.alt))
			}
		}
		for name := range m {
			if strings.HasPrefix(name, "dm-") && !known[name] {
				bad = append(bad, "untouched key present: "+name)
			}
		}
		showErr(t, c.Replicas[i].Node+": delete/overwrite final state wrong", bad)
	}
	showErr(t, "DELETE of a key whose last acked write was a PUT answered 404", del404)
	present := 0
	for _, dk := range keys {
		if dk.state >= 0 {
			present++
		}
	}
	c.Logf("delete mix: %d keys, %d PUT, %d DELETE, %d indeterminate; %d present at the end", len(keys), nPut.Load(), nDel.Load(), nIndet.Load(), present)
}

// --- W5: read-heavy staleness metric ---------------------------------------------

// readHeavy: the checker's single writer plus 16 readers over the replicas.
// For each acked write, the time from its ack to the first read at each
// replica that shows it (or newer) is a staleness sample: a metric, not an
// assertion (reads are bounded stale by design, docs/cds-ha.md).
func readHeavy(t *testing.T, c *Cluster, k *Checker) {
	type seen struct {
		at time.Time
		v  int
	}
	var mu sync.Mutex
	trans := map[[2]string][]seen{} // [node, key] -> increasing values
	var nreads atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for r := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i := r % len(c.Replicas)
			node := c.Replicas[i].Node
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, path := range []string{"/allowlist", "/dev/ha/secrets"} {
					resp := c.Get(i, path)
					at := time.Now()
					if resp.Err != nil || resp.Code != http.StatusOK {
						if resp.Err == nil {
							k.recordAux(i, http.MethodGet, path, resp.Code, string(resp.Body))
						}
						time.Sleep(20 * time.Millisecond)
						continue
					}
					nreads.Add(1)
					var vals map[string]int
					if path == "/allowlist" {
						vals, _ = parseAllow(resp.Body)
					} else {
						vals, _ = parseSecrets(resp.Body)
					}
					mu.Lock()
					for key, v := range vals {
						id := [2]string{node, key}
						h := trans[id]
						if len(h) == 0 || v > h[len(h)-1].v {
							trans[id] = append(h, seen{at, v})
						}
					}
					mu.Unlock()
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}
	hold(30 * time.Second)
	l := c.WaitLeader(10 * time.Second)
	f := followerVoter(t, c, l)
	c.Isolate(f)
	hold(10 * time.Second)
	c.Heal()
	hold(20 * time.Second)
	close(stop)
	wg.Wait()
	k.mu.Lock()
	ops := slices.Clone(k.ops)
	k.mu.Unlock()
	type stat struct {
		Samples, Unseen, BeforeAck int
		P50, P99, Max      time.Duration
	}
	out := map[string]stat{}
	for _, r := range c.Replicas {
		var d []time.Duration
		st := stat{}
		for _, op := range ops {
			if !op.Acked() {
				continue
			}
			h := trans[[2]string{r.Node, op.Kind + "/" + op.Key}]
			j := slices.IndexFunc(h, func(s seen) bool { return s.v >= op.Seq })
			if j < 0 {
				st.Unseen++
				continue
			}
			lag := h[j].at.Sub(op.End)
			if lag < 0 {
				st.BeforeAck++
				lag = 0
			}
			d = append(d, lag)
		}
		slices.Sort(d)
		st.Samples = len(d)
		if len(d) > 0 {
			st.P50, st.P99, st.Max = d[len(d)/2], d[len(d)*99/100], d[len(d)-1]
		}
		out[r.Node] = st
		c.Logf("staleness %s (isolated: %v): samples=%d p50=%s p99=%s max=%s visible-before-ack=%d never-seen=%d",
			r.Node, r.Idx == f, st.Samples, st.P50.Round(time.Millisecond), st.P99.Round(time.Millisecond), st.Max.Round(time.Millisecond), st.BeforeAck, st.Unseen)
	}
	c.Logf("read-heavy: %d served reads by 16 readers", nreads.Load())
	raw, _ := json.MarshalIndent(map[string]any{"isolated": c.Replicas[f].Node, "per_replica": out, "reads": nreads.Load()}, "", "  ")
	_ = os.WriteFile(filepath.Join(c.LogDir, "w5-staleness.json"), raw, 0o644)
}

func TestWorkload(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "W1-hot-key", run: hotKey},
		{name: "W2-large-bodies", extraArgs: historyBound, run: largeBodies},
		{name: "W3-wide-keyspace", extraArgs: historyBound, run: wideKeyspace},
		{name: "W4-delete-overwrite-mix", run: deleteMix},
		{name: "W5-read-heavy-staleness", writers: 1, run: readHeavy},
	})
}
