//go:build integration

// Package cdsha_test is the multi-process integration test of CDS-HA v2:
// five real `c8s cds` processes on loopback addresses, a fault-injecting
// proxy between every pair of peers, and a history checker. Run it with
// test/integration/cdsha/run.sh or
//
//	go test -tags integration ./test/integration/cdsha/...
package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

const (
	clusterID   = "itc"
	decreeNS    = "decrees"
	measurement = "m-it"
	// Loopback ranges no other test uses: replicas advertise 127.0.77.N (the
	// fault proxy listens there) and really listen on 127.0.78.N.
	advertiseNet = "127.0.77."
	bindNet      = "127.0.78."
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
	if runtime.GOOS != "linux" {
		fmt.Println("cdsha integration test needs Linux (127.0.0.0/8 on lo)")
		os.Exit(0)
	}
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
		root, err := repoRoot()
		if err != nil {
			panic(err)
		}
		cmd := exec.Command("go", "build", "-tags", "c8s_dev", "-o", binPath, "./cmd/c8s")
		cmd.Dir, cmd.Stdout, cmd.Stderr = root, os.Stdout, os.Stderr
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

func repoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	return filepath.Dir(strings.TrimSpace(string(out))), nil
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
}

// Cluster is five replica slots, the fault net, and the operator's keys.
type Cluster struct {
	t        *testing.T
	N        int
	Seats    int
	Replicas []*Replica
	Net      *faultNet
	Dir      string
	KubeDir  string
	LogDir   string
	HTTPPort int
	PeerPort int

	OpKey      *ecdsa.PrivateKey
	OpKeyPath  string // private, for the CLI
	OpPubPath  string
	RecKey     *ecdsa.PrivateKey
	RecKeyPath string
	RecPubPath string
	attestAPI  *httptest.Server
	ExtraFlags []string
	genesisAt  time.Time
	client     *http.Client
}

type clusterOpts struct {
	n, seats  int
	noGenesis bool
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

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newKeyPair(t *testing.T, dir, name string) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	priv := filepath.Join(dir, name+".key")
	pubp := filepath.Join(dir, name+".pub")
	writePEM(t, priv, "EC PRIVATE KEY", der)
	writePEM(t, pubp, "PUBLIC KEY", pub)
	return k, priv, pubp
}

// NewCluster starts n replica processes (seats voters) and waits for all to
// serve one cluster born from a Genesis decree naming n1.
func NewCluster(t *testing.T, o clusterOpts) *Cluster {
	t.Helper()
	if o.n == 0 {
		o.n = 5
	}
	if o.seats == 0 {
		o.seats = 3
	}
	dir := t.TempDir()
	c := &Cluster{t: t, N: o.n, Seats: o.seats, Net: newFaultNet(), Dir: dir, KubeDir: filepath.Join(dir, "kube"),
		LogDir:   filepath.Join(logRoot, strings.ReplaceAll(t.Name(), "/", "_")),
		HTTPPort: freePortOn(t, o.n), PeerPort: freePortOn(t, o.n),
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64, DisableKeepAlives: false}}}
	for c.PeerPort == c.HTTPPort {
		c.PeerPort = freePortOn(t, o.n)
	}
	_ = os.RemoveAll(c.LogDir)
	if err := os.MkdirAll(c.LogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	c.OpKey, c.OpKeyPath, c.OpPubPath = newKeyPair(t, dir, "decree")
	c.RecKey, c.RecKeyPath, c.RecPubPath = newKeyPair(t, dir, "recovery")
	c.attestAPI = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(c.attestAPI.Close)
	srcOf := func(ip string) int {
		if s, ok := strings.CutPrefix(ip, advertiseNet); ok {
			if i, err := strconv.Atoi(s); err == nil && i >= 1 && i <= o.n {
				return i - 1
			}
		}
		return -1
	}
	for i := 0; i < o.n; i++ {
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
		for _, r := range c.Replicas {
			c.Kill(r.Idx)
		}
		c.Net.close()
		if t.Failed() {
			t.Logf("replica logs: %s", c.LogDir)
		}
	})
	if !o.noGenesis {
		c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: "genesis", Kind: cdsha.Genesis,
			BootstrapNode: "n1", ExpiresAt: time.Now().Add(time.Hour)}, nil)
	}
	for i := range c.Replicas {
		c.Start(i, false)
	}
	if !o.noGenesis {
		c.WaitAllServing(60 * time.Second)
		c.genesisAt = time.Now()
		// Operator tokens are refused until the clock skew (1 s) has passed
		// since Genesis.
		time.Sleep(1500 * time.Millisecond)
	}
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
		"--ha-seats", strconv.Itoa(c.Seats), "--ha-max-non-voters", "8",
		"--ha-heartbeat", timing.heartbeat.String(), "--ha-election", timing.election.String(),
		"--ha-lease", timing.lease.String(), "--ha-dead-after", timing.deadAfter.String(),
		"--ha-stabilize", timing.stabilize.String(), "--ha-apply-timeout", timing.apply.String(),
		"--ha-tick", timing.tick.String(), "--ha-backup-interval", timing.backup.String(),
	}
	args = append(args, c.ExtraFlags...)
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
	r.cmd = nil
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

// WaitDecreeStatus waits until the decree has a status.
func (c *Cluster) WaitDecreeStatus(name string, timeout time.Duration) cdsha.DecreeStatus {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, ok := c.DecreeStatus(name); ok {
			return st
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("decree %s got no status in %s", name, timeout)
	return cdsha.DecreeStatus{}
}

// Token is a single-use operator token for one request.
func (c *Cluster) Token(method, path string, body []byte) string {
	sum := sha256.Sum256(body)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"htm": method, "htu": path, "pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
		"jti": randHex(8),
	}).SignedString(c.OpKey)
	if err != nil {
		panic(err)
	}
	return tok
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Response is one HTTP exchange; Err is set when there was no response.
type Response struct {
	Code   int
	Header http.Header
	Body   []byte
	Err    error
}

// Do sends one request to replica i. token "" sends none; "op" mints one.
func (c *Cluster) Do(ctx context.Context, i int, method, path string, body []byte, token string) Response {
	if token == "op" {
		token = c.Token(method, path, body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Replicas[i].Base+path, bytes.NewReader(body))
	if err != nil {
		return Response{Err: err}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
	return c.Do(ctx, i, http.MethodGet, path, nil, "")
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
	start := time.Now()
	for {
		if c.FullyServing(i) && c.Get(i, "/readyz").Code == http.StatusOK {
			return time.Since(start)
		}
		if time.Since(start) > timeout {
			c.t.Fatalf("%s not ready after %s: %s", c.Replicas[i].Node, timeout, c.StatusAll())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// WaitServing waits for the listed replicas to serve.
func (c *Cluster) WaitServing(ids []int, timeout time.Duration) time.Duration {
	c.t.Helper()
	start := time.Now()
	for _, i := range ids {
		for !c.FullyServing(i) {
			if time.Since(start) > timeout {
				c.t.Fatalf("%s not serving after %s (status %s)", c.Replicas[i].Node, timeout, c.StatusLine(i))
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return time.Since(start)
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
	start := time.Now()
	for {
		st, ok := c.Status(i)
		if !ok || !st.Serving {
			return time.Since(start)
		}
		if time.Since(start) > timeout {
			c.t.Fatalf("%s still serving after %s: %s", c.Replicas[i].Node, timeout, c.StatusLine(i))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Leader is the index of the replica that reports itself leader, or -1.
func (c *Cluster) Leader() int {
	for i := range c.Replicas {
		if !c.Running(i) {
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
	start := time.Now()
	for time.Since(start) < timeout {
		for i := range c.Replicas {
			if contains(exclude, i) || !c.Running(i) {
				continue
			}
			if st, ok := c.Status(i); ok && st.State == "Leader" && st.Serving {
				return i
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("no leader (excluding %v) after %s: %s", exclude, timeout, c.StatusAll())
	return -1
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
		if !contains(v, i) {
			out = append(out, i)
		}
	}
	return out
}

// WaitVoters waits until the leader reports n voters, each on a running
// replica.
func (c *Cluster) WaitVoters(n int, timeout time.Duration) {
	c.t.Helper()
	start := time.Now()
	for time.Since(start) < timeout {
		v := c.Voters()
		ok := len(v) == n
		for _, i := range v {
			ok = ok && c.Running(i)
		}
		if ok {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	c.t.Fatalf("voters never reached %d: %s", n, c.StatusAll())
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
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

// RunCLI runs the c8s binary with args and returns its combined output.
func (c *Cluster) RunCLI(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binPath, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
