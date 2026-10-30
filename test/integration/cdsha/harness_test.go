//go:build integration && linux

// Package cdsha_test runs a CDS HA cluster of real processes: three `c8s cds`
// replicas of one cluster on loopback addresses, each with its own
// attestation-api, and an operator that posts the decrees they act on to them
// or leaves them on the cluster's fake S3 board.
//
// Run it with test/integration/cdsha/run.sh. Linux only: the replicas answer
// at 127.0.77.0/24.
package cdsha_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsboard/boardtest"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	clusterID = "lane"
	// replicaNet is the loopback range the replicas answer at, one address
	// each, numbered from one as the configuration's replica entries are.
	replicaNet = "127.0.77."
	// clientPort and peerPort are fixed in every cluster.
	clientPort = 8443
	peerPort   = clientPort + 1
	// bucket is the board bucket the cluster's decrees may lie in.
	bucket = "c8s-boards"
	// clockSkewSeconds is every replica's --jwt-clock-skew, which is also how
	// long after the cluster starts an operator token stays refused.
	clockSkewSeconds = 1
	logTail          = 40
	// maxAnswer bounds a replica's answer, the largest of which is the
	// allowlist document.
	maxAnswer = 1 << 20
	// noAnswer is a replica that answered nothing, which no caller reads as a refusal.
	noAnswer = 0
)

// nextCDSImage is the CDS image an image roll adds beside the one the replicas run.
const nextCDSImage = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

type nodeImage struct {
	name string
	mrtd string
}

// The node images of an upgrade: the one the cluster starts out certifying,
// and the one the nodes are relaunched on.
var (
	seededNodeImage = nodeImage{
		name: "node",
		mrtd: strings.Repeat("ab", 48),
	}
	nextNodeImage = nodeImage{
		name: "node-next",
		mrtd: strings.Repeat("bc", 48),
	}
)

// The node image sets of that upgrade: the one the configuration seeds and
// the Genesis decree carries, the one accepting both images, and the one
// retiring the old image.
var (
	nodeImagesDocument  = nodeImagesCertifying(seededNodeImage)
	upgradingNodeImages = nodeImagesCertifying(seededNodeImage, nextNodeImage)
	nextNodeImages      = nodeImagesCertifying(nextNodeImage)
)

// A node pin document, as `ha decree node-images --nodes` reads one.
func nodeImagesCertifying(images ...nodeImage) string {
	entries := make([]string, 0, len(images))
	for _, image := range images {
		entries = append(entries, fmt.Sprintf(`{"name":%q,"mrtd":%q}`, image.name, image.mrtd))
	}
	return `{"schema_version":"1","tee":"tdx","measurements":[` + strings.Join(entries, ",") + `]}`
}

const seededWorkload = "attestation-api"

// binaries are the programs the harness runs: the CDS, built with the tag that
// serves a replica set, and the attestation-api a replica attests through.
type binaries struct {
	cds  string
	api  string
	logs string
}

var built binaries

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cdsha-it-")
	if err != nil {
		panic(err)
	}
	built = binaries{
		cds:  filepath.Join(dir, "c8s"),
		api:  filepath.Join(dir, "mock-attestation"),
		logs: filepath.Join(dir, "logs"),
	}
	for _, build := range [][]string{
		{"build", "-tags", "c8s_dev", "-o", built.cds, "github.com/confidential-dot-ai/c8s/cmd/c8s"},
		{"build", "-o", built.api, "github.com/confidential-dot-ai/c8s/test/mock-attestation"},
	} {
		cmd := exec.Command("go", build...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("build:", err)
			os.Exit(1)
		}
	}
	fmt.Println("cdsha integration: logs in", built.logs)
	code := m.Run()
	if code == 0 {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

// shape is the cluster a scenario runs on: the voter seats its configuration
// seeds, and the replicas that boot it.
type shape struct {
	voters   int
	replicas int
}

// cluster is one CDS HA cluster under test: the launch file its replicas
// boot, the board its operator may decree on, and the replica processes.
type cluster struct {
	t          *testing.T
	dir        string
	config     []byte
	configPath string
	board      *boardtest.Server
	roots      string
	operator   *ecdsa.PrivateKey
	signer     *operatorauth.Signer
	// recovery is the key the cluster seals its backups to, as the operator
	// keeps it offline.
	recovery *ecdsa.PrivateKey
	// client verifies through an attestation-api of its own, so no scenario's
	// kill takes the verifier with it.
	client   *http.Client
	replicas []*replica
	// decreed is the replica the operator decreed the Genesis of, and
	// genesisIntent the decree that started the cluster.
	decreed       *replica
	genesisIntent string
}

// replica is one CDS VM: the address it answers at, the attestation-api
// inside it, and the process serving the cluster.
type replica struct {
	index  int
	host   string
	base   string
	apiURL string
	db     string
	// Counts the CDS images this VM has been replaced with.
	rolls int
	cds   *process
	// locked is the connection holding this VM's allowlist database away from
	// the process serving the cluster.
	locked *sql.Conn
}

// A fault of one VM's disk: the next log entry its state machine applies fails
// in its own database. A reserved connection is the only way sqlite keeps the
// transaction that holds the lock open.
func (c *cluster) lockAllowlist(r *replica) {
	c.t.Helper()
	pool, err := sql.Open("sqlite", r.db)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { pool.Close() })
	held, err := pool.Conn(context.Background())
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := held.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		c.t.Fatalf("hold the allowlist database of replica %d: %v", r.index, err)
	}
	r.locked = held
	c.t.Cleanup(func() { c.freeAllowlist(r) })
	c.logf("took the allowlist database of replica %d away from it", r.index)
}

// Gives the database back to the process that replaces the stuck replica.
func (c *cluster) freeAllowlist(r *replica) {
	c.t.Helper()
	if r.locked == nil {
		return
	}
	held := r.locked
	r.locked = nil
	if _, err := held.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		c.t.Errorf("give the allowlist database of replica %d back: %v", r.index, err)
	}
	if err := held.Close(); err != nil {
		c.t.Errorf("close the connection holding the allowlist database of replica %d: %v",
			r.index, err)
	}
	c.logf("gave the allowlist database of replica %d back", r.index)
}

// The digest hooks of the replica's store never see the change, as they would
// not see memory or a disk corrupting its state.
func (c *cluster) changeAllowlistUnderIt(r *replica) {
	c.t.Helper()
	outside, err := sql.Open("sqlite", "file:"+r.db+"?_pragma=busy_timeout(10000)")
	if err != nil {
		c.t.Fatal(err)
	}
	defer outside.Close()
	changed, err := outside.Exec(`UPDATE workload_entry SET name = 'changed-under-replica-' || name`)
	if err != nil {
		c.t.Fatalf("change the allowlist database of replica %d under it: %v", r.index, err)
	}
	rows, err := changed.RowsAffected()
	if err != nil || rows == 0 {
		c.t.Fatalf("the harness changed %d rows of the allowlist database of replica %d: %v", rows, r.index, err)
	}
	c.logf("changed %d rows of the allowlist database of replica %d under it", rows, r.index)
}

// An exit is what the replica's unit restarts.
func (c *cluster) waitExit(r *replica, within time.Duration) {
	c.t.Helper()
	exited := fmt.Sprintf("the process of replica %d to exit", r.index)
	c.waitFor(exited, within, func() bool {
		return !c.running(r)
	})
	if code := r.cds.cmd.ProcessState.ExitCode(); code == 0 {
		c.t.Errorf("the process of replica %d exited %d; a unit restarts on a failure",
			r.index, code)
	}
	c.logf("the process of replica %d exited", r.index)
}

func (c *cluster) running(r *replica) bool {
	select {
	case <-r.cds.exited:
		return false
	default:
		return true
	}
}

// replicaHost numbers the addresses from one, as the configuration's replica
// entries are.
func replicaHost(index int) string {
	return replicaNet + strconv.Itoa(index+1)
}

// newCluster boots the replicas of a cluster of this shape, decrees the
// Genesis of the first, and returns once every replica serves.
func newCluster(t *testing.T, size shape) *cluster {
	t.Helper()
	c := &cluster{t: t, dir: t.TempDir()}
	c.requireFreeAddresses(size.replicas)
	c.board = boardtest.Start(bucket)
	t.Cleanup(c.board.Close)
	c.roots = c.boardRoots()
	c.operator = newKey(t)
	c.recovery = newKey(t)
	c.signer = c.operatorSigner()
	c.configure(size)
	c.client = c.attestedClient(testutil.TestMeasurement)
	for i := range size.replicas {
		c.replicas = append(c.replicas, c.start(i))
	}
	c.genesis(c.replicas[0])
	c.waitServing(time.Minute)
	return c
}

// requireFreeAddresses refuses to run where the replicas cannot answer: the
// harness binds fixed addresses, so anything else on them is a clear failure
// rather than a stuck replica.
func (c *cluster) requireFreeAddresses(replicas int) {
	c.t.Helper()
	for i := range replicas {
		for _, port := range []int{clientPort, peerPort} {
			address := net.JoinHostPort(replicaHost(i), strconv.Itoa(port))
			listener, err := net.Listen("tcp", address)
			if err != nil {
				c.t.Fatalf("the harness needs %s free: %v", address, err)
			}
			listener.Close()
		}
	}
}

// configure writes the launch file every replica of the cluster boots: one
// document serves them all, and nothing in it names one replica.
func (c *cluster) configure(size shape) {
	c.t.Helper()
	addresses := make([]string, 0, size.replicas)
	for i := range size.replicas {
		addresses = append(addresses, replicaHost(i))
	}
	document, err := yaml.Marshal(map[string]any{
		"schemaVersion":      cdsconfig.SchemaVersion,
		"clusterID":          clusterID,
		"operatorPublicKeys": string(publicKeyPEM(c.t, &c.operator.PublicKey)),
		"workloads": `{"schema":"c8s.allowlist/v1","workloads":{"` + seededWorkload +
			`":{"label":"ghcr.io/x/` + seededWorkload + `:v1","containers":[{"digest":"sha256:` +
			strings.Repeat("11", 32) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`,
		"nodes":        nodeImagesDocument,
		"nodeCIDRs":    []string{"10.0.0.0/24"},
		"leafDNSNames": []string{"workload." + clusterID + ".svc"},
		"ha": map[string]any{
			"replicas": addresses,
			"voters":   size.voters,
			"board": map[string]any{
				"endpoint": c.board.Endpoint(),
				"bucket":   bucket,
			},
			"recoveryKey": string(publicKeyPEM(c.t, &c.recovery.PublicKey)),
		},
	})
	if err != nil {
		c.t.Fatal(err)
	}
	c.config = document
	c.configPath = filepath.Join(c.dir, "cds-config.yaml")
	write(c.t, c.configPath, c.config)
}

// start runs the attestation-api that reports replica i's launch, and the CDS
// process serving the cluster at its address.
func (c *cluster) start(i int) *replica {
	c.t.Helper()
	r := &replica{
		index:  i,
		host:   replicaHost(i),
		db:     filepath.Join(c.dir, fmt.Sprintf("allowlist-%d.db", i)),
		apiURL: c.attestationAPI(fmt.Sprintf("replica-%d", i), testutil.TestMeasurement),
	}
	r.base = fmt.Sprintf("https://%s:%d", r.host, clientPort)
	c.restart(r)
	return r
}

// attestationAPI runs one attestation-api on this host's loopback, reporting
// this CDS image and the launch file of this cluster's replicas.
func (c *cluster) attestationAPI(name, measurement string) string {
	c.t.Helper()
	port := freePort(c.t)
	launch := runtimemeasure.HostData(c.config)
	c.run(name+"-attestation-api", built.api, nil, []string{
		"PORT=" + strconv.Itoa(port),
		"MEASUREMENT=" + measurement,
		"HOST_DATA=" + hex.EncodeToString(launch[:]),
	})
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	c.waitFor("the attestation-api of "+name, 30*time.Second, func() bool {
		response, err := http.Get(url + "/health") //nolint:noctx // a local health check in a test
		if err != nil {
			return false
		}
		response.Body.Close()
		return true
	})
	return url
}

// restart runs a replica's CDS process again, as a systemd restart does: a
// new member of the cluster, over an allowlist database the log refills.
func (c *cluster) restart(r *replica) {
	c.t.Helper()
	r.cds = c.run(fmt.Sprintf("replica-%d-cds", r.index), built.cds, []string{
		"cds",
		"--config", c.configPath,
		"--attestation-api-url", r.apiURL,
		"--allowlist-db", r.db,
		"--host", r.host,
		"--port", strconv.Itoa(clientPort),
		"--jwt-clock-skew", strconv.Itoa(clockSkewSeconds),
		"--log-level", "debug",
	}, []string{"SSL_CERT_FILE=" + c.roots})
}

// kill ends a replica's CDS process, as a lost VM does. The attestation-api
// inside that VM keeps answering.
func (c *cluster) kill(r *replica) {
	c.t.Helper()
	r.cds.kill()
	c.logf("killed the process of replica %d", r.index)
}

// process is one program the harness runs, with its output in a file a failed
// test prints.
type process struct {
	cmd    *exec.Cmd
	log    string
	exited chan struct{}
}

func (c *cluster) run(name, binary string, args, env []string) *process {
	c.t.Helper()
	if err := os.MkdirAll(built.logs, 0o755); err != nil {
		c.t.Fatal(err)
	}
	log, err := os.CreateTemp(built.logs, strings.ReplaceAll(c.t.Name(), "/", "_")+"-"+name+"-*.log")
	if err != nil {
		c.t.Fatal(err)
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = log
	cmd.Stderr = log
	// The children die with the test binary, however it ends.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	p := &process{cmd: cmd, log: log.Name(), exited: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		log.Close()
		close(p.exited)
	}()
	c.t.Cleanup(func() {
		p.kill()
		if c.t.Failed() {
			c.t.Logf("%s log: %s\n%s", name, p.log, tail(p.log))
		}
	})
	return p
}

func (p *process) kill() {
	select {
	case <-p.exited:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	<-p.exited
}

func tail(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(cannot read %s: %v)", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) > logTail {
		lines = lines[len(lines)-logTail:]
	}
	return strings.Join(lines, "\n")
}

// attestedClient reads the replicas over armTLS, verified against the images
// the cluster's pin document names, bound to the launch file they boot.
func (c *cluster) attestedClient(measurement string, alsoAccepted ...string) *http.Client {
	c.t.Helper()
	var pins armtls.Pins
	for i, accepted := range append([]string{measurement}, alsoAccepted...) {
		digest, err := hex.DecodeString(accepted)
		if err != nil {
			c.t.Fatal(err)
		}
		pins.Images = append(pins.Images, remote.ImagePin{
			Name:       fmt.Sprintf("cds-%d", i),
			Digest:     digest,
			LaunchFile: c.config,
		})
	}
	client, err := armtls.NewVerifyingHTTPClient(pins, c.attestationAPI("the operator", testutil.TestMeasurement))
	if err != nil {
		c.t.Fatal(err)
	}
	return client
}

// boardRoots writes the fake board's certificate where a replica's system
// roots read it: the board speaks HTTPS, as the cluster's own does, and it is
// the one endpoint a replica verifies that way.
func (c *cluster) boardRoots() string {
	c.t.Helper()
	endpoint := strings.TrimPrefix(c.board.Endpoint(), "https://")
	conn, err := tls.Dial("tcp", endpoint, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the certificate is what this reads
	if err != nil {
		c.t.Fatal(err)
	}
	defer conn.Close()
	served := conn.ConnectionState().PeerCertificates
	if len(served) != 1 {
		c.t.Fatalf("the board serves a chain of %d certificates, want its one self-signed leaf", len(served))
	}
	roots := filepath.Join(c.dir, "board-roots.pem")
	write(c.t, roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: served[0].Raw}))
	return roots
}

// decreeOnTheBoard leaves one signed decree on the cluster's board, as an
// operator with their own credentials for the store does.
func (c *cluster) decreeOnTheBoard(d cdsdecree.Decree) string {
	c.t.Helper()
	object, err := json.Marshal(c.sign(d))
	if err != nil {
		c.t.Fatal(err)
	}
	c.board.Put(path.Join(clusterID, "decrees", d.IntentID+".json"), object)
	return d.IntentID
}

// genesis decrees the Genesis of r, as an operator who read its member id and
// mesh CA over the attested channel and posted the decree back on it does.
func (c *cluster) genesis(r *replica) {
	c.t.Helper()
	c.genesisCertifying(r, nodeImagesDocument, 0)
}

// The decree carries the node image set, so a cluster started again certifies
// what the operator names now.
func (c *cluster) genesisCertifying(r *replica, nodeImages string, resumeVersion uint64) {
	c.t.Helper()
	reported := c.awaitStatus(r)
	pins, err := cdsdecree.NewPinDocument([]byte(testutil.CDSPinDocument(testutil.TestMeasurement, string(c.config))))
	if err != nil {
		c.t.Fatal(err)
	}
	nodes, err := cdsdecree.NewNodeImages([]byte(nodeImages))
	if err != nil {
		c.t.Fatal(err)
	}
	genesis := cdsdecree.Decree{
		ClusterID:     clusterID,
		IntentID:      cdsdecree.NewIntentID(),
		Kind:          cdsdecree.Genesis,
		ExpiresAt:     time.Now().Add(time.Hour),
		CDSPins:       pins,
		NodePins:      nodes,
		TargetMember:  reported.ID,
		TargetAddress: fmt.Sprintf("%s:%d", r.host, clientPort),
		IssuedAtMS:    time.Now().UnixMilli(),
		GenesisCA:     reported.GenesisCA,
		ResumeVersion: resumeVersion,
	}
	c.decree(r, genesis)
	c.genesisIntent = genesis.IntentID
	c.decreed = r
	c.logf("decreed the Genesis of replica %d, member %s", r.index, reported.ID)
}

// sign signs one decree with the key the cluster's configuration pins.
func (c *cluster) sign(d cdsdecree.Decree) cdsdecree.Signed {
	c.t.Helper()
	signed, err := cdsdecree.Sign(d, c.operator)
	if err != nil {
		c.t.Fatal(err)
	}
	return signed
}

// decree signs one decree and posts it to a replica, as the operator's CLI
// does over the attested channel, and reports what the replica answered.
func (c *cluster) decree(to *replica, d cdsdecree.Decree) cdsha.Delivered {
	c.t.Helper()
	object, err := json.Marshal(c.sign(d))
	if err != nil {
		c.t.Fatal(err)
	}
	code, answer := c.send(to, http.MethodPost, "/ha/decrees", object, nil)
	if code != http.StatusOK {
		c.t.Fatalf("posting the %s decree to replica %d: %d %s", d.Kind, to.index, code, bytes.TrimSpace(answer))
	}
	var delivered cdsha.Delivered
	if err := json.Unmarshal(answer, &delivered); err != nil {
		c.t.Fatalf("what replica %d made of the %s decree: %v", to.index, d.Kind, err)
	}
	return delivered
}

// Names the CDS images a replica of the cluster may run from then on.
func (c *cluster) decreePins(to *replica, version uint64, measurements ...string) (string, cdsha.Delivered) {
	c.t.Helper()
	decree := cdsdecree.Decree{
		ClusterID:   clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.UpdateMeasurements,
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseVersion: version,
		CDSPins:     c.pinDocument(measurements...),
	}
	return decree.IntentID, c.decree(to, decree)
}

// The Admit decree a replica holding no cluster acts on, so a replica of a
// new image reaches a leader still running the old one.
func (c *cluster) decreeAdmit(to *replica, measurements ...string) cdsha.Delivered {
	c.t.Helper()
	return c.decree(to, cdsdecree.Decree{
		ClusterID:    clusterID,
		IntentID:     cdsdecree.NewIntentID(),
		Kind:         cdsdecree.Admit,
		ExpiresAt:    time.Now().Add(time.Hour),
		CDSPins:      c.pinDocument(measurements...),
		TargetMember: c.awaitStatus(to).ID,
	})
}

// Carries the whole set of node images the cluster is to certify.
func (c *cluster) decreeNodeImages(to *replica, version uint64, document string) (string, cdsha.Delivered) {
	c.t.Helper()
	nodes, err := cdsdecree.NewNodeImages([]byte(document))
	if err != nil {
		c.t.Fatal(err)
	}
	decree := cdsdecree.Decree{
		ClusterID:   clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.SetNodeImages,
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseVersion: version,
		NodePins:    nodes,
	}
	return decree.IntentID, c.decree(to, decree)
}

// By name, and none from a replica that does not serve its cluster yet.
func (c *cluster) certifiedNodeImages(r *replica) []string {
	code, body := c.get(r, "/measurements")
	switch code {
	case http.StatusOK:
	case http.StatusServiceUnavailable, noAnswer:
		return nil
	default:
		c.t.Fatalf("replica %d serves /measurements = %d %s", r.index, code, body)
	}
	published, err := refvalues.ParseRendered(body)
	if err != nil {
		c.t.Fatalf("replica %d publishes measurements that do not parse: %v: %s", r.index, err, body)
	}
	names := make([]string, 0, len(published.Images))
	for _, image := range published.Images {
		names = append(names, image.Name)
	}
	return slices.Sorted(slices.Values(names))
}

// Every replica publishes these node images and no others.
func (c *cluster) allPublish(images ...nodeImage) bool {
	want := make([]string, 0, len(images))
	for _, image := range images {
		want = append(want, image.name)
	}
	slices.Sort(want)
	for _, r := range c.replicas {
		if !slices.Equal(c.certifiedNodeImages(r), want) {
			return false
		}
	}
	return true
}

// Every replica names version as the command that last replaced the set.
func (c *cluster) allAtNodeImagesVersion(version uint64) bool {
	for _, r := range c.replicas {
		reported, answered := c.status(r)
		if !answered || reported.NodeImagesVersion != version {
			return false
		}
	}
	return true
}

// decreeRotateKey posts a RotateKey decree to a replica.
func (c *cluster) decreeRotateKey(to *replica, version uint64) (string, cdsha.Delivered) {
	c.t.Helper()
	decree := cdsdecree.Decree{
		ClusterID:   clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.RotateKey,
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseVersion: version,
	}
	return decree.IntentID, c.decree(to, decree)
}

// Each image bound to the launch file every replica of the cluster boots.
func (c *cluster) pinDocument(measurements ...string) *cdsdecree.PinDocument {
	c.t.Helper()
	launchFile := strconv.Quote(string(c.config))
	entries := make([]string, 0, len(measurements))
	for i, measurement := range measurements {
		entries = append(entries, fmt.Sprintf(`{"name":"cds-%d","measurement":%q,"launch_file":%s}`, i, measurement, launchFile))
	}
	pins, err := cdsdecree.NewPinDocument([]byte(
		`{"schema_version":"2","tee":"sev-snp","measurements":[` + strings.Join(entries, ",") + `]}`))
	if err != nil {
		c.t.Fatal(err)
	}
	return pins
}

// The process ends and starts again beside an attestation-api reporting the
// new image, at the address the cluster's replica entries resolve to.
func (c *cluster) rollImage(r *replica, measurement string) {
	c.t.Helper()
	c.kill(r)
	r.rolls++
	r.apiURL = c.attestationAPI(fmt.Sprintf("replica-%d-roll-%d", r.index, r.rolls), measurement)
	c.restart(r)
	c.logf("replica %d runs CDS image %s now", r.index, measurement)
}

// The member is alive and answers nothing, as under a host that drops its packets.
func (c *cluster) pause(r *replica) {
	c.t.Helper()
	c.signal(r, syscall.SIGSTOP)
	c.logf("paused the process of replica %d", r.index)
}

func (c *cluster) resume(r *replica) {
	c.t.Helper()
	c.signal(r, syscall.SIGCONT)
	c.logf("resumed the process of replica %d", r.index)
}

func (c *cluster) signal(r *replica, sig syscall.Signal) {
	c.t.Helper()
	if err := r.cds.cmd.Process.Signal(sig); err != nil {
		c.t.Fatalf("signal %s to replica %d: %v", sig, r.index, err)
	}
}

// Sorted, and empty while the cluster has no leader to report them.
func (c *cluster) seated() []string {
	return slices.Sorted(slices.Values(c.leaderReport().Voters))
}

func (c *cluster) withoutAVote() []string {
	return slices.Sorted(slices.Values(c.leaderReport().NonVoters))
}

// An empty report while no replica leads.
func (c *cluster) leaderReport() cdsha.Status {
	leading := c.leader()
	if leading == nil {
		return cdsha.Status{}
	}
	reported, _ := c.status(leading)
	return reported
}

func (c *cluster) holdingAVote(besides *replica) *replica {
	c.t.Helper()
	voters := c.seated()
	for _, candidate := range c.others(besides) {
		if reported, ok := c.status(candidate); ok && slices.Contains(voters, reported.ID) {
			return candidate
		}
	}
	c.t.Fatalf("no replica besides %d holds a voter seat; the leader holds %v",
		besides.index, voters)
	return nil
}

// The gate between the replicas of a roll.
func (c *cluster) waitRollSafe(within time.Duration) {
	c.t.Helper()
	c.waitFor("the cluster to report one replica of it replaceable", within, func() bool {
		safe := c.leaderReport().RollSafe
		return safe != nil && safe.OK
	})
}

// The seats a scenario empties are taken by the replicas left over, so a
// scenario that cuts a voter off waits for every replica to be in first.
func (c *cluster) waitEveryReplicaJoined(within time.Duration) {
	c.t.Helper()
	c.waitFor("every replica to be a member of the cluster", within, func() bool {
		leading := c.leader()
		return leading != nil && len(c.members(leading)) == len(c.replicas)
	})
}

func (c *cluster) decreeVoters(to *replica, version uint64, seats int) (string, cdsha.Delivered) {
	c.t.Helper()
	decree := cdsdecree.Decree{
		ClusterID:   clusterID,
		IntentID:    cdsdecree.NewIntentID(),
		Kind:        cdsdecree.SetVoters,
		ExpiresAt:   time.Now().Add(time.Hour),
		BaseVersion: version,
		Voters:      seats,
	}
	return decree.IntentID, c.decree(to, decree)
}

// allApplied reports every replica holding the decree, at the version it produced.
func (c *cluster) allApplied(intent string, version uint64) bool {
	for _, r := range c.replicas {
		reported, answered := c.status(r)
		if !answered || !reported.Serving.OK || reported.Version != version {
			return false
		}
		if !c.recorded(r, intent, version) {
			return false
		}
	}
	return true
}

// recorded reports a replica whose record of applied decrees names the decree.
func (c *cluster) recorded(r *replica, intent string, version uint64) bool {
	code, body := c.get(r, "/ha/decrees")
	if code != http.StatusOK {
		return false
	}
	var applied []cdsha.DecreeRecord
	if json.Unmarshal(body, &applied) != nil {
		return false
	}
	return slices.ContainsFunc(applied, func(record cdsha.DecreeRecord) bool {
		return record.Decree.Decree.IntentID == intent && record.Version == version
	})
}

// servedCA is the fingerprint of the certificate a replica serves at /ca.
func (c *cluster) servedCA(r *replica) string {
	c.t.Helper()
	code, body := c.get(r, "/ca")
	if code != http.StatusOK {
		c.t.Fatalf("replica %d serves /ca = %d %s, want the cluster's mesh CA", r.index, code, body)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		c.t.Fatalf("replica %d serves a mesh CA that is no PEM certificate: %s", r.index, body)
	}
	return certutil.CertFingerprint(block.Bytes)
}

// status is what a replica reports about its cluster, and whether it answered.
func (c *cluster) status(r *replica) (cdsha.Status, bool) {
	var reported cdsha.Status
	code, body := c.get(r, "/ha/status")
	if code != http.StatusOK || json.Unmarshal(body, &reported) != nil {
		return reported, false
	}
	return reported, true
}

// awaitStatus is the first report a starting replica answers with.
func (c *cluster) awaitStatus(r *replica) cdsha.Status {
	c.t.Helper()
	var reported cdsha.Status
	c.waitFor(fmt.Sprintf("replica %d to report itself", r.index), 30*time.Second, func() bool {
		var answered bool
		reported, answered = c.status(r)
		return answered && reported.ID != ""
	})
	return reported
}

func (c *cluster) get(r *replica, route string) (int, []byte) {
	return c.send(r, http.MethodGet, route, nil, nil)
}

// post writes one route of a replica over the attested channel, as the
// operator restoring a cluster does.
func (c *cluster) post(r *replica, route string, body []byte) (int, []byte) {
	return c.send(r, http.MethodPost, route, body, nil)
}

// put writes one route of a replica with an operator token.
func (c *cluster) put(r *replica, route string, body []byte) (int, []byte) {
	return c.send(r, http.MethodPut, route, body, c.signer)
}

func (c *cluster) send(r *replica, method, route string, body []byte, operator *operatorauth.Signer) (int, []byte) {
	request, err := http.NewRequest(method, r.base+route, bytes.NewReader(body)) //nolint:noctx // the client carries the deadline
	if err != nil {
		c.t.Fatal(err)
	}
	if operator != nil {
		authorization, err := operator.Authorization(method, route, body)
		if err != nil {
			c.t.Fatal(err)
		}
		request.Header.Set("Authorization", authorization)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return noAnswer, []byte(err.Error())
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer))
	if err != nil {
		c.t.Fatal(err)
	}
	return response.StatusCode, answer
}

// serving are the replicas that serve their cluster: each reports serving it
// and answers the readiness a client is routed by.
func (c *cluster) serving() []*replica {
	var answered []*replica
	for _, r := range c.replicas {
		reported, ok := c.status(r)
		if !ok || !reported.Serving.OK {
			continue
		}
		if code, _ := c.get(r, "/readyz"); code != http.StatusOK {
			continue
		}
		answered = append(answered, r)
	}
	return answered
}

// leader is the replica the cluster elected, or nil while it has none.
func (c *cluster) leader() *replica {
	for _, r := range c.replicas {
		reported, ok := c.status(r)
		if ok && reported.State == raft.Leader.String() && reported.Serving.OK {
			return r
		}
	}
	return nil
}

func (c *cluster) others(r *replica) []*replica {
	var rest []*replica
	for _, other := range c.replicas {
		if other != r {
			rest = append(rest, other)
		}
	}
	return rest
}

func (c *cluster) waitServing(within time.Duration) {
	c.t.Helper()
	c.waitFor(fmt.Sprintf("%d replicas serving the cluster", len(c.replicas)), within, func() bool {
		return len(c.serving()) == len(c.replicas)
	})
}

// waitLeader waits for the cluster to elect a leader that serves it.
func (c *cluster) waitLeader(within time.Duration) *replica {
	c.t.Helper()
	var leading *replica
	c.waitFor("a leader", within, func() bool {
		leading = c.leader()
		return leading != nil
	})
	return leading
}

// waitVoter and waitWithoutAVote wait until the cluster's configuration gives
// a replica the place a scenario needs before it stops that replica: a vote
// counts towards the majority its loss takes away, and a replica without one
// counts towards none.
func (c *cluster) waitVoter(r *replica, within time.Duration) {
	c.t.Helper()
	c.waitFor(fmt.Sprintf("replica %d to hold a vote", r.index), within, func() bool {
		return c.holdsAVote(r)
	})
}

func (c *cluster) waitWithoutAVote(r *replica, within time.Duration) {
	c.t.Helper()
	c.waitFor(fmt.Sprintf("replica %d to be a member without a vote", r.index), within, func() bool {
		return c.joinedWithoutAVote(r)
	})
}

// members are the member ids the cluster's configuration names, as r reports it.
func (c *cluster) members(r *replica) []string {
	reported, answered := c.status(r)
	if !answered {
		return nil
	}
	return append(reported.Voters, reported.NonVoters...)
}

func (c *cluster) holdsAVote(r *replica) bool {
	reported, answered := c.status(r)
	return answered && slices.Contains(reported.Voters, reported.ID)
}

func (c *cluster) joinedWithoutAVote(r *replica) bool {
	reported, answered := c.status(r)
	return answered && slices.Contains(reported.NonVoters, reported.ID)
}

// waitFor fails the test with what every replica reported if the condition
// never holds.
func (c *cluster) waitFor(what string, within time.Duration, holds func() bool) {
	c.t.Helper()
	deadline := time.Now().Add(within)
	for {
		if holds() {
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("waited %s for %s; the replicas report:%s", within, what, c.reports())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (c *cluster) reports() string {
	var out strings.Builder
	for _, r := range c.replicas {
		reported, answered := c.status(r)
		if !answered {
			code, body := c.get(r, "/ha/status")
			fmt.Fprintf(&out, "\n  replica %d: no report (%d %s)", r.index, code, bytes.TrimSpace(body))
			continue
		}
		fmt.Fprintf(&out, "\n  replica %d: %+v", r.index, reported)
	}
	return out.String()
}

func (c *cluster) logf(format string, args ...any) {
	c.t.Helper()
	c.t.Logf("%s %s", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

func (c *cluster) operatorSigner() *operatorauth.Signer {
	c.t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.operator)
	if err != nil {
		c.t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		c.t.Fatal(err)
	}
	return signer
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicKeyPEM(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func write(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
