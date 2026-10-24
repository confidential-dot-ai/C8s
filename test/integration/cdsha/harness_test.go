//go:build integration && linux

// Package cdsha_test is the multi-process integration test of CDS-HA
// (docs/cds-ha.md): five real `c8s cds` processes on loopback addresses, a
// fault-injecting proxy between every pair of peers, and a history checker.
// Run it with test/integration/cdsha/run.sh or
//
//	go test -tags integration ./test/integration/cdsha/...
package cdsha_test

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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	clusterID   = "itc"
	decreeNS    = "decrees"
	measurement = "m-it"
	// Loopback ranges no other test uses: replicas advertise 127.0.77.N (the
	// fault proxy listens there) and really listen on 127.0.78.N.
	advertiseNet = "127.0.77."
	bindNet      = "127.0.78."
	// replicas processes, seats of them voters.
	replicas, seats = 5, 3
)

// Timing, about half the defaults, so faults resolve quickly.
var timing = struct {
	heartbeat, election, lease, deadAfter, stabilize, apply, tick, backup time.Duration
}{500 * time.Millisecond, 500 * time.Millisecond, 2500 * time.Millisecond, 8 * time.Second,
	2 * time.Second, 5 * time.Second, 250 * time.Millisecond, time.Second}

var (
	binPath string
	logRoot string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cdsha-it-")
	if err != nil {
		panic(err)
	}
	logRoot = os.Getenv("CDSHA_IT_LOGS")
	if logRoot == "" {
		logRoot = filepath.Join(dir, "logs")
	}
	binPath = os.Getenv("CDSHA_IT_BIN")
	if binPath == "" {
		binPath = filepath.Join(dir, "c8s")
		cmd := exec.Command("go", "build", "-tags", "c8s_dev", "-o", binPath, "github.com/confidential-dot-ai/c8s/cmd/c8s")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("build c8s:", err)
			os.Exit(1)
		}
	}
	fmt.Println("cdsha integration: binary", binPath, "logs", logRoot)
	code := m.Run()
	if code == 0 && os.Getenv("CDSHA_IT_KEEP") == "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

// Replica is one CDS process slot (a "node"): the process may be killed and
// restarted; its addresses stay.
type Replica struct {
	Idx       int
	Node      string
	Advertise string // proxy, what peers dial
	Bind      string // the process listens here (HTTP and peer port)
	Base      string // http://Bind:httpPort

	mu     sync.Mutex
	cmd    *exec.Cmd
	exited chan struct{}
	inc    int // incarnation
	db     string
	frozen bool // SIGSTOPped by Freeze
}

// Cluster is five replica slots, the fault net, and the operator's keys.
type Cluster struct {
	t                   *testing.T
	Replicas            []*Replica
	Net                 *faultNet
	Dir                 string
	KubeDir             string
	LogDir              string
	HTTPPort            int
	PeerPort            int
	heartbeat, election time.Duration
	extraArgs           []string

	OpKey      *ecdsa.PrivateKey
	OpKeyPath  string // private, for the CLI
	OpPubPath  string
	RecKeyPath string
	RecPubPath string
	attestAPI  *httptest.Server
	signer     *operatorauth.Signer // the CLI's operator token minter
	client     *http.Client
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// freePortOn finds a port free on every replica address (advertise and bind).
func freePortOn(t *testing.T, n int) int {
	t.Helper()
	for range 50 {
		p := freePort(t)
		ok := true
		for i := 1; i <= n && ok; i++ {
			for _, net0 := range []string{advertiseNet, bindNet} {
				l, err := net.Listen("tcp", net.JoinHostPort(fmt.Sprintf("%s%d", net0, i), strconv.Itoa(p)))
				if err != nil {
					ok = false
					break
				}
				l.Close()
			}
		}
		if ok {
			return p
		}
	}
	t.Fatal("no port free on every replica address")
	return 0
}

// newKeyPair writes a P-256 key pair as dir/name.key (PKCS#8) and
// dir/name.pub; it returns the key, the private PEM and both paths.
func newKeyPair(t *testing.T, dir, name string) (k *ecdsa.PrivateKey, privPEM []byte, priv, pubp string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err = certutil.MarshalECKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, pubp = filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	if err := os.WriteFile(priv, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubp, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o600); err != nil {
		t.Fatal(err)
	}
	return k, privPEM, priv, pubp
}

// NewCluster starts the replica processes and waits for all to serve one
// cluster born from a Genesis decree naming n1.
func NewCluster(t *testing.T) *Cluster {
	t.Helper()
	return newClusterWithRaftTiming(t, timing.heartbeat, timing.election)
}

func newClusterWithRaftTiming(t *testing.T, heartbeat, election time.Duration, extraArgs ...string) *Cluster {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(logRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// A test name repeats under -count; retain each invocation's evidence.
	logDir, err := os.MkdirTemp(logRoot, strings.ReplaceAll(t.Name(), "/", "_")+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("replica logs: %s", logDir)
	c := &Cluster{t: t, extraArgs: extraArgs, heartbeat: heartbeat, election: election, Net: newFaultNet(), Dir: dir, KubeDir: filepath.Join(dir, "kube"),
		LogDir:   logDir,
		HTTPPort: freePortOn(t, replicas), PeerPort: freePortOn(t, replicas),
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}}
	for c.PeerPort == c.HTTPPort {
		c.PeerPort = freePortOn(t, replicas)
	}
	var opPEM []byte
	c.OpKey, opPEM, c.OpKeyPath, c.OpPubPath = newKeyPair(t, dir, "decree")
	_, _, c.RecKeyPath, c.RecPubPath = newKeyPair(t, dir, "recovery")
	signer, err := operatorauth.NewSignerFromKeyPEM(opPEM)
	if err != nil {
		t.Fatal(err)
	}
	c.signer = signer
	c.attestAPI = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(c.attestAPI.Close)
	srcOf := func(ip string) int {
		if s, ok := strings.CutPrefix(ip, advertiseNet); ok {
			if i, err := strconv.Atoi(s); err == nil && i >= 1 && i <= replicas {
				return i - 1
			}
		}
		return -1
	}
	for i := range replicas {
		r := &Replica{Idx: i, Node: fmt.Sprintf("n%d", i+1),
			Advertise: fmt.Sprintf("%s%d", advertiseNet, i+1), Bind: fmt.Sprintf("%s%d", bindNet, i+1)}
		r.Base = fmt.Sprintf("http://%s:%d", r.Bind, c.HTTPPort)
		c.Replicas = append(c.Replicas, r)
		if err := c.Net.listen(net.JoinHostPort(r.Advertise, strconv.Itoa(c.PeerPort)),
			net.JoinHostPort(r.Bind, strconv.Itoa(c.PeerPort)), i, srcOf); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		// Capture every live replica before killing any process. Status contains
		// HA metadata only, not keys, secret values, or database contents.
		if t.Failed() {
			for _, r := range c.Replicas {
				if c.Running(r.Idx) {
					st, ok := c.Status(r.Idx)
					c.Logf("failure status %s reachable=%t: %+v", r.Node, ok, st)
				}
			}
		}
		for _, r := range c.Replicas {
			c.Kill(r.Idx)
		}
		c.Net.close()
		if t.Failed() {
			t.Logf("replica logs: %s", c.LogDir)
		}
	})
	c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "genesis", Kind: cdsha.Genesis,
		BootstrapNode: "n1", ExpiresAt: time.Now().Add(time.Hour)}, nil)
	for i := range c.Replicas {
		c.Start(i, false)
	}
	c.WaitAllServing(60 * time.Second)
	// Operator tokens are refused until the clock skew (1 s) has passed
	// since Genesis.
	time.Sleep(1500 * time.Millisecond)
	return c
}

// Start launches replica i's process. keepDB reuses the allowlist database
// of the previous incarnation (a pod restart); otherwise a fresh one (a VM
// restart).
func (c *Cluster) Start(i int, keepDB bool) {
	c.t.Helper()
	r := c.Replicas[i]
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		c.t.Fatalf("%s already running", r.Node)
	}
	r.inc++
	if !keepDB || r.db == "" {
		r.db = filepath.Join(c.Dir, fmt.Sprintf("%s-%d.db", r.Node, r.inc))
	}
	var peers []string
	for _, o := range c.Replicas {
		if o.Idx != i {
			peers = append(peers, net.JoinHostPort(o.Advertise, strconv.Itoa(c.PeerPort)))
		}
	}
	args := []string{"cds",
		"--armtls-platform", "", "--host", r.Bind, "--port", strconv.Itoa(c.HTTPPort), "--log-level", "info",
		"--attestation-api-url", c.attestAPI.URL, "--allowlist-db", r.db,
		"--operator-keys", c.OpPubPath, "--jwt-clock-skew", "1",
		"--rate-limit", "100000", "--rate-burst", "100000",
		"--secrets-max-paths", "200000", "--secrets-max-paths-per-workload", "100000",
		"--sandbox-inventory-cidr", "127.0.0.0/8",
		"--ha-cluster-id", clusterID, "--ha-decree-namespace", decreeNS,
		"--ha-peers", strings.Join(peers, ","), "--ha-advertise-ip", r.Advertise, "--ha-port", strconv.Itoa(c.PeerPort),
		"--ha-node-name", r.Node, "--ha-attestor", "mock", "--ha-measurement", measurement, "--ha-replica-pins", measurement,
		"--ha-operator-key", c.OpPubPath, "--ha-recovery-key", c.RecPubPath,
		"--ha-seats", strconv.Itoa(seats),
		"--ha-heartbeat", c.heartbeat.String(), "--ha-election", c.election.String(),
		"--ha-lease", timing.lease.String(), "--ha-dead-after", timing.deadAfter.String(),
		"--ha-stabilize", timing.stabilize.String(), "--ha-apply-timeout", timing.apply.String(),
		"--ha-tick", timing.tick.String(), "--ha-backup-interval", timing.backup.String(),
	}
	args = append(args, c.extraArgs...)
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), "C8S_DEV_KUBE_DIR="+c.KubeDir, "C8S_DEV_TEST_ROUTES=1")
	logf, err := os.Create(filepath.Join(c.LogDir, fmt.Sprintf("%s.%d.log", r.Node, r.inc)))
	if err != nil {
		c.t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); logf.Close(); close(exited) }()
	r.cmd, r.exited = cmd, exited
	c.Logf("start %s (incarnation %d, pid %d)", r.Node, r.inc, cmd.Process.Pid)
}

// Kill sends SIGKILL to replica i and waits for it to exit.
func (c *Cluster) Kill(i int) {
	r := c.Replicas[i]
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return
	}
	_ = r.cmd.Process.Signal(syscall.SIGKILL)
	<-r.exited
	r.cmd, r.frozen = nil, false
	c.Logf("killed %s", r.Node)
}

// Running reports whether replica i's process is alive.
func (c *Cluster) Running(i int) bool {
	r := c.Replicas[i]
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return false
	}
	select {
	case <-r.exited:
		return false
	default:
		return true
	}
}

// Restart kills and starts replica i.
func (c *Cluster) Restart(i int, keepDB bool) {
	c.Kill(i)
	c.Start(i, keepDB)
}

func (c *Cluster) Logf(format string, args ...any) {
	c.t.Helper()
	c.t.Logf("%s "+format, append([]any{time.Now().Format("15:04:05.000")}, args...)...)
}

// --- network faults ---------------------------------------------------------

// Isolate cuts replica i from every other replica (both ways).
func (c *Cluster) Isolate(i int) {
	for j := range c.Replicas {
		if j != i {
			c.Net.Update(i, j, func(l *Link) { l.Blackhole = true })
			c.Net.Update(j, i, func(l *Link) { l.Blackhole = true })
		}
	}
	c.Logf("isolate %s", c.Replicas[i].Node)
}

// Partition splits the replicas into groups that cannot reach each other.
func (c *Cluster) Partition(groups ...[]int) {
	group := map[int]int{}
	for g, ids := range groups {
		for _, i := range ids {
			group[i] = g
		}
	}
	for i := range c.Replicas {
		for j := range c.Replicas {
			if i != j && group[i] != group[j] {
				c.Net.Update(i, j, func(l *Link) { l.Blackhole = true })
			}
		}
	}
	c.Logf("partition %v", groups)
}

// Heal clears every network fault.
func (c *Cluster) Heal() {
	c.Net.HealAll()
	c.Logf("heal")
}

// --- operator side ----------------------------------------------------------

// PutDecree signs d (with key, or the operator key) and writes it to the
// decree "namespace".
func (c *Cluster) PutDecree(d cdsha.Decree, key *ecdsa.PrivateKey) string {
	c.t.Helper()
	if key == nil {
		key = c.OpKey
	}
	sd, err := cdsha.SignDecree(d, key)
	if err != nil {
		c.t.Fatal(err)
	}
	cm, err := cdsha.DecreeConfigMap(decreeNS, sd)
	if err != nil {
		c.t.Fatal(err)
	}
	c.PutConfigMap(cm)
	return cm.Name
}

// PutConfigMap writes an object into the shared "API server" directory.
func (c *Cluster) PutConfigMap(cm *corev1.ConfigMap) {
	c.t.Helper()
	raw, err := json.Marshal(cm)
	if err != nil {
		c.t.Fatal(err)
	}
	dir := filepath.Join(c.KubeDir, decreeNS)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		c.t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".tmp-test-"+cm.Name)
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		c.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, cm.Name+".json")); err != nil {
		c.t.Fatal(err)
	}
}

// ConfigMaps lists the objects in the decree namespace with label key=value.
func (c *Cluster) ConfigMaps(key, value string) []corev1.ConfigMap {
	c.t.Helper()
	ents, _ := os.ReadDir(filepath.Join(c.KubeDir, decreeNS))
	var out []corev1.ConfigMap
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(c.KubeDir, decreeNS, e.Name()))
		if err != nil {
			continue
		}
		var cm corev1.ConfigMap
		if json.Unmarshal(raw, &cm) == nil && cm.Labels[key] == value {
			out = append(out, cm)
		}
	}
	return out
}

// DecreeStatus reads the status the leader wrote on a decree object.
func (c *Cluster) DecreeStatus(name string) (cdsha.DecreeStatus, bool) {
	raw, err := os.ReadFile(filepath.Join(c.KubeDir, decreeNS, name+".json"))
	if err != nil {
		return cdsha.DecreeStatus{}, false
	}
	var cm corev1.ConfigMap
	if json.Unmarshal(raw, &cm) != nil || cm.Data["status"] == "" {
		return cdsha.DecreeStatus{}, false
	}
	var st cdsha.DecreeStatus
	_ = json.Unmarshal([]byte(cm.Data["status"]), &st)
	return st, true
}

// waitFor polls cond every 100 ms until it holds and returns the time it
// took; after timeout it fails the test with what().
func (c *Cluster) waitFor(timeout time.Duration, cond func() bool, what func() string) time.Duration {
	c.t.Helper()
	start := time.Now()
	err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, timeout, true,
		func(context.Context) (bool, error) { return cond(), nil })
	if err != nil {
		c.t.Fatalf("after %s: %s", timeout, what())
	}
	return time.Since(start)
}

// never polls bad every 200 ms for d and fails the test on the first
// violation it reports.
func (c *Cluster) never(d time.Duration, bad func() string) {
	c.t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if msg := bad(); msg != "" {
			c.t.Error(msg)
			return
		}
	}
}

// WaitDecreeStatus waits until the decree has a status.
func (c *Cluster) WaitDecreeStatus(name string, timeout time.Duration) cdsha.DecreeStatus {
	c.t.Helper()
	var st cdsha.DecreeStatus
	c.waitFor(timeout, func() (ok bool) { st, ok = c.DecreeStatus(name); return ok },
		func() string { return "decree " + name + " got no status" })
	return st
}

// Response is one HTTP exchange; Err is set when there was no response.
type Response struct {
	Code   int
	Header http.Header
	Body   []byte
	Err    error
}

// Do sends one request to replica i; op signs it with the operator key
// through operatorauth.Signer, as the CLI does.
func (c *Cluster) Do(ctx context.Context, i int, method, path string, body []byte, op bool) Response {
	req, err := http.NewRequestWithContext(ctx, method, c.Replicas[i].Base+path, bytes.NewReader(body))
	if err != nil {
		return Response{Err: err}
	}
	if op {
		auth, err := c.signer.Authorization(method, path, body)
		if err != nil {
			return Response{Err: err}
		}
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Response{Err: err}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return Response{Code: resp.StatusCode, Header: resp.Header, Body: b, Err: err}
}

// Get is Do(GET) with a short timeout.
func (c *Cluster) Get(i int, path string) Response {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.Do(ctx, i, http.MethodGet, path, nil, false)
}

// Status is replica i's /ha/status (ok=false when unreachable).
func (c *Cluster) Status(i int) (cdsha.Status, bool) {
	r := c.Get(i, "/ha/status")
	var st cdsha.Status
	if r.Err != nil || r.Code != http.StatusOK || json.Unmarshal(r.Body, &st) != nil {
		return st, false
	}
	return st, true
}

// FullyServing: /ha/status says serving and the full server (not the
// pre-join one) answers /ca.
func (c *Cluster) FullyServing(i int) bool {
	st, ok := c.Status(i)
	if !ok || !st.Serving {
		return false
	}
	return c.Get(i, "/ca").Code == http.StatusOK
}

// WaitReady waits until replica i's full server answers /readyz 200 (what
// a DaemonSet's readiness probe sees).
func (c *Cluster) WaitReady(i int, timeout time.Duration) time.Duration {
	c.t.Helper()
	return c.waitFor(timeout, func() bool { return c.FullyServing(i) && c.Get(i, "/readyz").Code == http.StatusOK },
		func() string { return c.Replicas[i].Node + " not ready:" + c.StatusAll() })
}

// WaitServing waits for the listed replicas to serve, one after another.
func (c *Cluster) WaitServing(ids []int, timeout time.Duration) time.Duration {
	c.t.Helper()
	pending := ids
	return c.waitFor(timeout, func() bool {
		for len(pending) > 0 && c.FullyServing(pending[0]) {
			pending = pending[1:]
		}
		return len(pending) == 0
	}, func() string { return "not serving: " + c.StatusLine(pending[0]) })
}

// WaitAllServing waits for every running replica to serve.
func (c *Cluster) WaitAllServing(timeout time.Duration) time.Duration {
	c.t.Helper()
	return c.WaitServing(c.RunningIDs(), timeout)
}

// RunningIDs are the replicas whose process is alive.
func (c *Cluster) RunningIDs() []int {
	var out []int
	for i := range c.Replicas {
		if c.Running(i) {
			out = append(out, i)
		}
	}
	return out
}

// WaitNotServing waits until replica i reports serving=false (or is down).
func (c *Cluster) WaitNotServing(i int, timeout time.Duration) time.Duration {
	c.t.Helper()
	return c.waitFor(timeout, func() bool { st, ok := c.Status(i); return !ok || !st.Serving },
		func() string { return "still serving: " + c.StatusLine(i) })
}

// Leader is the index of a running replica, other than the excluded ones,
// that reports itself a serving leader, or -1.
func (c *Cluster) Leader(exclude ...int) int {
	for i := range c.Replicas {
		if slices.Contains(exclude, i) || !c.Running(i) {
			continue
		}
		if st, ok := c.Status(i); ok && st.State == "Leader" && st.Serving {
			return i
		}
	}
	return -1
}

// WaitLeader waits for a serving leader other than the excluded replicas.
func (c *Cluster) WaitLeader(timeout time.Duration, exclude ...int) int {
	c.t.Helper()
	l := -1
	c.waitFor(timeout, func() bool { l = c.Leader(exclude...); return l >= 0 },
		func() string { return fmt.Sprintf("no leader (excluding %v):%s", exclude, c.StatusAll()) })
	return l
}

// Voters are the replica indexes whose current member is a voter, in the
// leader's view.
func (c *Cluster) Voters() []int {
	l := c.Leader()
	if l < 0 {
		return nil
	}
	st, _ := c.Status(l)
	var out []int
	for _, v := range st.Voters {
		node, _, _ := strings.Cut(v, "/")
		for _, r := range c.Replicas {
			if r.Node == node {
				out = append(out, r.Idx)
			}
		}
	}
	return out
}

// NonVoterIDs are the running replicas that are not voters.
func (c *Cluster) NonVoterIDs() []int {
	v := c.Voters()
	var out []int
	for _, i := range c.RunningIDs() {
		if !slices.Contains(v, i) {
			out = append(out, i)
		}
	}
	return out
}

// WaitVoters waits until the leader reports n voters, each the member of
// a running replica's current incarnation. A voter left behind by a killed
// incarnation of the same node (its member ID differs) does not count: it
// holds a seat no live process can vote with.
func (c *Cluster) WaitVoters(n int, timeout time.Duration) {
	c.t.Helper()
	c.waitFor(timeout, func() bool {
		l := c.Leader()
		if l < 0 {
			return false
		}
		st, _ := c.Status(l)
		if len(st.Voters) != n {
			return false
		}
		for _, v := range st.Voters {
			node, _, _ := strings.Cut(v, "/")
			idx := slices.IndexFunc(c.Replicas, func(r *Replica) bool { return r.Node == node })
			if idx < 0 || !c.Running(idx) {
				return false
			}
			cur, ok := c.Status(idx)
			if !ok || cur.ID != v {
				return false
			}
		}
		return true
	}, func() string { return fmt.Sprintf("voters never reached %d live current members:%s", n, c.StatusAll()) })
}

func (c *Cluster) StatusLine(i int) string {
	st, ok := c.Status(i)
	if !ok {
		return c.Replicas[i].Node + ": unreachable"
	}
	return fmt.Sprintf("%s: state=%s serving=%v epoch=%d applied=%d leader=%s voters=%d nonvoters=%d ca=%.8s",
		c.Replicas[i].Node, st.State, st.Serving, st.Epoch, st.AppliedIndex, st.Leader, len(st.Voters), len(st.NonVoters), st.CAFingerprint)
}

func (c *Cluster) StatusAll() string {
	var b strings.Builder
	for i := range c.Replicas {
		b.WriteString("\n  " + c.StatusLine(i))
	}
	return b.String()
}

// Backups reads the sealed backup objects of the cluster.
func (c *Cluster) Backups() []corev1.ConfigMap {
	return c.ConfigMaps(cdsha.LabelBackup, clusterID)
}
