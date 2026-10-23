//go:build integration && linux

package cdsha_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// gateMsg is the body of the freshness gate's 503 (ha.go haGate);
// preJoinMsg that of the pre-join server, before a replica has joined;
// unavailableMsg that of a write the replicated store could not commit
// (allowlist.ErrUnavailable, secrets.ErrUnavailable).
const (
	gateMsg        = "cds-ha: this replica is not serving"
	preJoinMsg     = "cds-ha: this replica has not joined the cluster yet"
	unavailableMsg = "replicated store unavailable"
)

// Op is one operator write and its outcome.
type Op struct {
	Kind string // "allow" or "secret"
	Key  string
	Seq  int
	End  time.Time
	Code int
	Err  string
	Body string
}

// Acked: the write returned success.
func (o Op) Acked() bool {
	if o.Kind == "allow" {
		return o.Code == http.StatusNoContent
	}
	return o.Code == http.StatusOK || o.Code == http.StatusCreated
}

// Definite: the write certainly did not take effect (refused before it was
// proposed, or rejected).
func (o Op) Definite() bool {
	if o.Acked() || o.Err != "" {
		return false
	}
	if o.Code == http.StatusServiceUnavailable && strings.Contains(o.Body, gateMsg) {
		return true
	}
	return o.Code >= 400 && o.Code < 500
}

// Checker runs writers and readers against a cluster and checks the
// history: no acked write lost, no value nobody wrote, monotonic reads.
type Checker struct {
	c       *Cluster
	writers int
	pause   time.Duration

	mu      sync.Mutex
	ops     []Op
	bad5xx  []string                  // 5xx that is not the freshness gate
	bad4xx  []string                  // a valid write refused as unauthorized or a replay
	obs     map[[2]int]map[string]int // [replica, inc] -> key -> highest seq seen
	regress []string                  // monotonic-read violations within one incarnation
	reads   atomic.Int64

	stop     chan struct{}
	wg       sync.WaitGroup
	paused   atomic.Bool
	inflight atomic.Int64
}

// Pause stops new writes (in-flight ones finish); Resume restarts them.
func (k *Checker) Pause() {
	k.paused.Store(true)
	for k.inflight.Load() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
}
func (k *Checker) Resume() { k.paused.Store(false) }

// badStatus: a 5xx that is not a retryable 503 (freshness gate, or a write
// the cluster could not commit).
func badStatus(code int, body string) bool {
	if code < 500 {
		return false
	}
	retryable := strings.Contains(body, gateMsg) || strings.Contains(body, preJoinMsg) || strings.Contains(body, unavailableMsg)
	return code != http.StatusServiceUnavailable || !retryable
}

// NewChecker prepares writers concurrent writers; each sleeps pause
// between writes.
func NewChecker(c *Cluster, writers int, pause time.Duration) *Checker {
	return &Checker{c: c, writers: writers, pause: pause, obs: map[[2]int]map[string]int{}, stop: make(chan struct{})}
}

// Start launches writers and one reader per replica.
func (k *Checker) Start() {
	for w := 0; w < k.writers; w++ {
		k.wg.Add(1)
		go k.writer(w)
	}
	for i := range k.c.Replicas {
		k.wg.Add(1)
		go k.reader(i)
	}
}

// Stop ends the load and waits for in-flight requests.
func (k *Checker) Stop() {
	close(k.stop)
	k.wg.Wait()
}

func (k *Checker) stopped() bool {
	select {
	case <-k.stop:
		return true
	default:
		return false
	}
}

// Writer w writes increasing sequence numbers to two keys of its own, one
// allowlist entry and one secret. After an indeterminate outcome it moves to
// a fresh generation of keys, so on every key all but the last write have a
// definite outcome and "the latest acked value is never lost" is exact.
func (k *Checker) writer(w int) {
	defer k.wg.Done()
	gen := map[string]int{"allow": 0, "secret": 0}
	seq := 0
	for !k.stopped() {
		for _, kind := range []string{"allow", "secret"} {
			if k.stopped() {
				return
			}
			k.inflight.Add(1)
			if k.paused.Load() {
				k.inflight.Add(-1)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			seq++
			key := fmt.Sprintf("w%dg%d", w, gen[kind])
			op := k.write(kind, key, seq)
			k.inflight.Add(-1)
			if !op.Acked() && !op.Definite() {
				gen[kind]++
			}
			if k.pause > 0 {
				select {
				case <-k.stop:
					return
				case <-time.After(k.pause):
				}
			}
		}
	}
}

func allowBody(key string, seq int) []byte {
	return []byte(fmt.Sprintf(`{"label":"ghcr.io/it/%s:v1","containers":[{"digest":"sha256:%064x","command":{"policy":"any"},"args":{"policy":"any"}}]}`, key, seq))
}

func (k *Checker) write(kind, key string, seq int) Op {
	running := k.c.RunningIDs()
	if len(running) == 0 {
		time.Sleep(100 * time.Millisecond)
		return Op{Kind: kind, Key: key, Seq: seq, Err: "no replica running"}
	}
	i := running[rand.IntN(len(running))]
	var path string
	var body []byte
	if kind == "allow" {
		path, body = "/allowlist/workloads/it-"+key, allowBody(key, seq)
	} else {
		path = "/secrets/it/" + key
		body, _ = json.Marshal(map[string]any{"value": base64.StdEncoding.EncodeToString([]byte(key + ":" + strconv.Itoa(seq))), "overwrite": true})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	op := Op{Kind: kind, Key: key, Seq: seq}
	r := k.c.Do(ctx, i, http.MethodPut, path, body, true)
	op.End, op.Code = time.Now(), r.Code
	if r.Err != nil {
		op.Err = r.Err.Error()
	}
	if len(r.Body) > 0 {
		op.Body = strings.TrimSpace(string(r.Body))
		if len(op.Body) > 300 {
			op.Body = op.Body[:300]
		}
	}
	k.mu.Lock()
	k.ops = append(k.ops, op)
	if badStatus(r.Code, op.Body) {
		k.bad5xx = append(k.bad5xx, fmt.Sprintf("%s PUT %s at %s: %d %s", op.End.Format("15:04:05.000"), path, k.c.Replicas[i].Node, r.Code, op.Body))
	}
	if r.Code == http.StatusUnauthorized || r.Code == http.StatusConflict {
		// Every write carries a fresh, valid, single-use token.
		k.bad4xx = append(k.bad4xx, fmt.Sprintf("%s PUT %s at %s: %d %s", op.End.Format("15:04:05.000"), path, k.c.Replicas[i].Node, r.Code, op.Body))
	}
	k.mu.Unlock()
	return op
}

// reader polls replica i and records the newest value of every key it
// serves.
func (k *Checker) reader(i int) {
	defer k.wg.Done()
	for !k.stopped() {
		k.readOnce(i)
		select {
		case <-k.stop:
			return
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func (k *Checker) readOnce(i int) {
	inc := k.c.Replicas[i].incarnation()
	vals := map[string]int{}
	ok := true
	for _, read := range []func(int) (map[string]int, bool){k.readAllow, k.readSecrets} {
		m, got := read(i)
		if !got {
			ok = false
			continue
		}
		for key, v := range m {
			vals[key] = v
		}
	}
	if !ok && len(vals) == 0 {
		return
	}
	k.reads.Add(1)
	now := time.Now()
	k.mu.Lock()
	defer k.mu.Unlock()
	id := [2]int{i, inc}
	seen := k.obs[id]
	if seen == nil {
		seen = map[string]int{}
		k.obs[id] = seen
	}
	for key, v := range vals {
		if prev, had := seen[key]; had && v < prev {
			k.regress = append(k.regress, fmt.Sprintf("%s %s inc %d: %s went %d -> %d", now.Format("15:04:05.000"), k.c.Replicas[i].Node, inc, key, prev, v))
		}
		seen[key] = max(seen[key], v)
	}
}

func (r *Replica) incarnation() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inc
}

func (k *Checker) note5xx(i int, path string, r Response) {
	if badStatus(r.Code, string(r.Body)) {
		k.mu.Lock()
		k.bad5xx = append(k.bad5xx, fmt.Sprintf("%s GET %s at %s: %d %s", time.Now().Format("15:04:05.000"), path, k.c.Replicas[i].Node, r.Code, strings.TrimSpace(string(r.Body))))
		k.mu.Unlock()
	}
}

// readAllow returns key -> seq for the checker's allowlist entries.
func (k *Checker) readAllow(i int) (map[string]int, bool) {
	r := k.c.Get(i, "/allowlist")
	k.note5xx(i, "/allowlist", r)
	if r.Err != nil || r.Code != http.StatusOK {
		return nil, false
	}
	m, err := parseAllow(r.Body)
	return m, err == nil
}

func parseAllow(body []byte) (map[string]int, error) {
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
		key, ok := strings.CutPrefix(name, "it-")
		if !ok || len(wl.Containers) == 0 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimPrefix(wl.Containers[0].Digest, "sha256:"), 16, 64)
		if err != nil {
			continue
		}
		out["allow/"+key] = int(v)
	}
	return out, nil
}

func (k *Checker) readSecrets(i int) (map[string]int, bool) {
	r := k.c.Get(i, "/dev/ha/secrets")
	k.note5xx(i, "/dev/ha/secrets", r)
	if r.Err != nil || r.Code != http.StatusOK {
		return nil, false
	}
	m, err := parseSecrets(r.Body)
	return m, err == nil
}

func parseSecrets(body []byte) (map[string]int, error) {
	var ents []struct {
		Path  string `json:"path"`
		Value []byte `json:"value"`
	}
	if err := json.Unmarshal(body, &ents); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, e := range ents {
		key, ok := strings.CutPrefix(strings.TrimPrefix(e.Path, "/"), "it/")
		if !ok {
			continue
		}
		_, n, ok := strings.Cut(string(e.Value), ":")
		if !ok {
			continue
		}
		v, err := strconv.Atoi(n)
		if err != nil {
			continue
		}
		out["secret/"+key] = v
	}
	return out, nil
}

// Snapshot is what one replica serves once the cluster is quiet.
type Snapshot struct {
	CA      string
	ETag    string
	Values  map[string]int
	Secrets string // canonical dump of the whole secret store
}

func (c *Cluster) snapshot(i int) (Snapshot, error) {
	st, ok := c.Status(i)
	if !ok || !st.Serving {
		return Snapshot{}, fmt.Errorf("%s not serving", c.Replicas[i].Node)
	}
	a := c.Get(i, "/allowlist")
	s := c.Get(i, "/dev/ha/secrets")
	if a.Code != http.StatusOK || s.Code != http.StatusOK {
		return Snapshot{}, fmt.Errorf("%s: allowlist %d secrets %d", c.Replicas[i].Node, a.Code, s.Code)
	}
	vals, err := parseAllow(a.Body)
	if err != nil {
		return Snapshot{}, err
	}
	sv, err := parseSecrets(s.Body)
	if err != nil {
		return Snapshot{}, err
	}
	for key, v := range sv {
		vals[key] = v
	}
	return Snapshot{CA: st.CAFingerprint, ETag: a.Header.Get("ETag"), Values: vals, Secrets: string(s.Body)}, nil
}

// Converge waits until every running replica serves the same CA, allowlist
// ETag and secret store; it returns the time it took.
func (c *Cluster) Converge(timeout time.Duration) (map[int]Snapshot, time.Duration, error) {
	start := time.Now()
	var snaps map[int]Snapshot
	var last error
	err := wait.PollUntilContextTimeout(context.Background(), 200*time.Millisecond, timeout, true, func(context.Context) (bool, error) {
		snaps, last = map[int]Snapshot{}, nil
		for _, i := range c.RunningIDs() {
			s, err := c.snapshot(i)
			if err != nil {
				last = err
				return false, nil
			}
			snaps[i] = s
		}
		if len(snaps) > 0 {
			last = sameSnapshots(c, snaps)
		}
		return len(snaps) > 0 && last == nil, nil
	})
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("no convergence in %s: %v", timeout, last)
	}
	return snaps, time.Since(start), nil
}

func sameSnapshots(c *Cluster, snaps map[int]Snapshot) error {
	var ref *Snapshot
	refIdx := -1
	for _, i := range slices.Sorted(maps.Keys(snaps)) {
		s := snaps[i]
		if ref == nil {
			ref, refIdx = &s, i
			continue
		}
		switch {
		case s.CA != ref.CA:
			return fmt.Errorf("CA differs: %s %.12s vs %s %.12s", c.Replicas[i].Node, s.CA, c.Replicas[refIdx].Node, ref.CA)
		case s.ETag != ref.ETag:
			return fmt.Errorf("ETag differs: %s %s vs %s %s", c.Replicas[i].Node, s.ETag, c.Replicas[refIdx].Node, ref.ETag)
		case s.Secrets != ref.Secrets:
			return fmt.Errorf("secret store differs: %s vs %s", c.Replicas[i].Node, c.Replicas[refIdx].Node)
		}
	}
	return nil
}

// Report is the outcome of a checked run.
type Report struct {
	Writes, Acked, Definite, Indeterminate int
	Reads                                  int64
	Lost                                   []string
	Invented                               []string
	Regress                                []string
	Bad5xx                                 []string
	Bad4xx                                 []string
	ConvergeIn                             time.Duration
	ConvergeErr                            error
}

func (r Report) String() string {
	return fmt.Sprintf("writes=%d acked=%d definite-fail=%d indeterminate=%d reads=%d lost=%d invented=%d regress=%d bad5xx=%d bad4xx=%d converge=%s",
		r.Writes, r.Acked, r.Definite, r.Indeterminate, r.Reads, len(r.Lost), len(r.Invented), len(r.Regress), len(r.Bad5xx), len(r.Bad4xx), r.ConvergeIn.Round(time.Millisecond))
}

// Check stops the load, waits for convergence and checks the history. The
// caller must have healed every fault first.
func (k *Checker) Check(convergeTimeout time.Duration) Report {
	k.Stop()
	var rep Report
	snaps, d, err := k.c.Converge(convergeTimeout)
	rep.ConvergeIn, rep.ConvergeErr = d, err
	k.mu.Lock()
	defer k.mu.Unlock()
	rep.Reads = k.reads.Load()
	rep.Regress = append(rep.Regress, k.regress...)
	rep.Bad5xx = append(rep.Bad5xx, k.bad5xx...)
	rep.Bad4xx = append(rep.Bad4xx, k.bad4xx...)
	maxAcked := map[string]int{}
	maxTried := map[string]int{}
	for _, op := range k.ops {
		rep.Writes++
		key := op.Kind + "/" + op.Key
		switch {
		case op.Acked():
			rep.Acked++
			maxAcked[key] = max(maxAcked[key], op.Seq)
		case op.Definite():
			rep.Definite++
		default:
			rep.Indeterminate++
		}
		if !op.Definite() {
			maxTried[key] = max(maxTried[key], op.Seq)
		}
	}
	for i, s := range snaps {
		for key, want := range maxAcked {
			if got, ok := s.Values[key]; !ok || got < want {
				rep.Lost = append(rep.Lost, fmt.Sprintf("%s: %s = %d (present %v), acked %d", k.c.Replicas[i].Node, key, got, ok, want))
			}
		}
		for key, got := range s.Values {
			if got > maxTried[key] {
				rep.Invented = append(rep.Invented, fmt.Sprintf("%s: %s = %d, highest possibly-applied write %d", k.c.Replicas[i].Node, key, got, maxTried[key]))
			}
		}
	}
	return rep
}

// Require fails the test on any violated rule.
func (k *Checker) Require(rep Report) {
	t := k.c.t
	t.Helper()
	t.Logf("checker: %s", rep)
	show := func(name string, xs []string) {
		if len(xs) == 0 {
			return
		}
		if len(xs) > 10 {
			xs = append(xs[:10:10], fmt.Sprintf("... and %d more", len(xs)-10))
		}
		t.Errorf("%s:\n  %s", name, strings.Join(xs, "\n  "))
	}
	if rep.ConvergeErr != nil {
		t.Errorf("convergence: %v\n%s", rep.ConvergeErr, k.c.StatusAll())
	}
	show("acknowledged writes lost", rep.Lost)
	show("values nobody wrote", rep.Invented)
	show("non-monotonic reads at one replica", rep.Regress)
	show("5xx other than a retryable 503", rep.Bad5xx)
	show("valid writes refused with 401/409", rep.Bad4xx)
	if rep.Acked == 0 {
		t.Error("no write was acknowledged")
	}
}
