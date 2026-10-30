package cdsha

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// A cluster of replica processes in one test: every replica has its own
// attestation-api on the loopback, its own stores, and its own peer port.
// They admit each other by the one CDS image of the test cluster.

// testTiming runs the replicas fast enough for a test to watch an election.
var testTiming = Timing{
	Heartbeat: 150 * time.Millisecond,
	Election:  150 * time.Millisecond,
	Lease:     time.Second,
	Apply:     3 * time.Second,
	Tick:      50 * time.Millisecond,
}

// The store limits every replica of the test cluster holds, which its policy
// makes the same ones.
const (
	maxTestSecretPaths     = 512
	maxTestPathsPerHolder  = 8
	maxTestSecretValue     = 4096
	testBindingLife        = time.Hour
	maxTestSandboxBindings = 100
)

// testCDSImage is the launch digest the replicas report and the pin decree names.
var testCDSImage = strings.Repeat("11", 48)

// testReplicaEntry is the replica entry every replica's discovery resolves.
const testReplicaEntry = "replicas.cds.test"

// liveReplica is one replica process: its attestation-api and its node.
type liveReplica struct {
	stub    *mockapi.Stub
	node    *Node
	resolve *addressBook
	cancel  context.CancelFunc
	done    chan struct{}
}

// liveCluster is a cluster of such replicas over shared launch values.
type liveCluster struct {
	t *testing.T
	cluster
	replicas []*liveReplica
}

func newLiveCluster(t *testing.T) *liveCluster {
	t.Helper()
	return &liveCluster{
		t:       t,
		cluster: newCluster(t),
	}
}

// genesis starts count replicas and starts the cluster on the first of them.
// They are then made voters, which the cluster does for itself later in this
// stack.
func (c *liveCluster) genesis(count int) {
	c.t.Helper()
	for range count {
		c.start()
	}
	first := c.replicas[0]
	c.decreeGenesis(first, count == 1)
	c.started(first)
	c.joined(len(c.replicas))
	for _, r := range c.replicas[1:] {
		c.addVoter(first, r)
	}
	c.settled(10 * time.Second)
}

// start is a fresh replica process of the cluster.
func (c *liveCluster) start() *liveReplica {
	c.t.Helper()
	stub := c.attestationAPI()
	resolve := &addressBook{}
	cfg := c.replicaConfig(stub)
	cfg.Resolve = resolve.resolve
	node, err := NewNode(cfg)
	if err != nil {
		c.t.Fatalf("new replica: %v", err)
	}
	if err := node.Start(); err != nil {
		c.t.Fatalf("start replica: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &liveReplica{
		stub:    stub,
		node:    node,
		resolve: resolve,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go func() {
		defer close(r.done)
		if err := node.Run(ctx); err != nil {
			c.t.Errorf("replica %s: %v", node.member, err)
		}
	}()
	c.replicas = append(c.replicas, r)
	c.resolveEachOther()
	c.t.Cleanup(func() {
		if slices.Contains(c.replicas, r) {
			c.stop(r)
		}
	})
	return r
}

// resolveEachOther makes every replica's entry answer with every peer address.
func (c *liveCluster) resolveEachOther() {
	addresses := c.peerAddresses()
	for _, r := range c.replicas {
		r.resolve.holds(addresses...)
	}
}

// peerAddress is where this replica's peer port answers.
func (r *liveReplica) peerAddress() netip.AddrPort {
	return r.node.mux.advert.endpoint
}

// peerAddresses is where every replica of the cluster answers.
func (c *liveCluster) peerAddresses() []netip.AddrPort {
	addresses := make([]netip.AddrPort, 0, len(c.replicas))
	for _, r := range c.replicas {
		addresses = append(addresses, r.peerAddress())
	}
	return addresses
}

// addressBook is what one replica's discovery resolves.
type addressBook struct {
	mu        sync.Mutex
	addresses []netip.AddrPort
	failing   bool
}

// holds makes the cluster's entry answer with these addresses, and answer at
// all.
func (b *addressBook) holds(addresses ...netip.AddrPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addresses = addresses
	b.failing = false
}

// fails makes the entry resolve to nothing, as a host's resolver may answer.
func (b *addressBook) fails() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failing = true
}

func (b *addressBook) resolve(_ context.Context, entry string) ([]netip.AddrPort, error) {
	if entry != testReplicaEntry {
		return nil, fmt.Errorf("the cluster has no replica entry %q", entry)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failing {
		return nil, errors.New("the resolver answered SERVFAIL")
	}
	return slices.Clone(b.addresses), nil
}

// posted hands one decree to r, as its operator does.
func (c *liveCluster) posted(r *liveReplica, signed cdsdecree.Signed) Delivered {
	c.t.Helper()
	delivered, err := r.node.TakeDecree(signed)
	if err != nil {
		c.t.Fatalf("replica %s would not take a decree of its operator: %v", r.node.member, err)
	}
	return delivered
}

// attestationAPI reports the CDS image of the test cluster.
func (c *liveCluster) attestationAPI() *mockapi.Stub {
	c.t.Helper()
	stub := mockapi.New(c.t)
	stub.SetPlatform(teetypes.PlatformSNP)
	stub.SetVerdict(snpVerdict(testCDSImage, testLaunchFile))
	return stub
}

// replicaConfig is what a replica runs on, over stores of its own.
func (c *liveCluster) replicaConfig(stub *mockapi.Stub) Config {
	c.t.Helper()
	return Config{
		Launch:         c.launch,
		LaunchFile:     testLaunchFile,
		Peer:           netip.MustParseAddrPort("127.0.0.1:0"),
		AttestationURL: stub.URL(),
		Timing:         testTiming,
		Replicas:       []string{testReplicaEntry},
		Allowlist:      inMemoryAllowlist(c.t),
		Secrets:        secrets.NewMemoryStore(maxTestSecretPaths, maxTestPathsPerHolder, maxTestSecretValue),
		Ledger:         sandboxledger.New(testBindingLife, maxTestSandboxBindings),
	}
}

// stop ends r: the process holding its log, and its peer port, are gone.
func (c *liveCluster) stop(r *liveReplica) {
	r.cancel()
	<-r.done
	c.replicas = slices.DeleteFunc(c.replicas, func(held *liveReplica) bool { return held == r })
}

// decreeGenesis posts the Genesis decree for r to r. alone is for the
// cluster whose replica set holds no other replica to answer.
func (c *liveCluster) decreeGenesis(r *liveReplica, alone bool) {
	c.t.Helper()
	c.posted(r, c.signDecree(c.genesisFor(r, alone)))
}

// genesisFor is the Genesis decree the operator signs for r.
func (c *liveCluster) genesisFor(r *liveReplica, alone bool) cdsdecree.Decree {
	c.t.Helper()
	decree := c.fixture(r).decree(cdsdecree.Genesis)
	decree.TargetMember = string(r.node.member)
	decree.GenesisCA = c.genesisCAOf(r)
	decree.Alone = alone
	return decree
}

// genesisCAOf is the mesh CA r installs if a Genesis decree names it.
func (c *liveCluster) genesisCAOf(r *liveReplica) string {
	c.t.Helper()
	fingerprint, err := r.node.GenesisCA()
	if err != nil {
		c.t.Fatalf("the mesh CA of replica %s: %v", r.node.member, err)
	}
	return fingerprint
}

// signDecree signs a decree with the cluster's operator key.
func (c *liveCluster) signDecree(d cdsdecree.Decree) cdsdecree.Signed {
	c.t.Helper()
	signed, err := cdsdecree.Sign(d, c.operator)
	if err != nil {
		c.t.Fatal(err)
	}
	return signed
}

// started waits until r holds the cluster the operator decreed it starts.
func (c *liveCluster) started(r *liveReplica) {
	c.t.Helper()
	eventually(c.t, 10*time.Second, "the decreed replica started the cluster", func() bool {
		return r.node.fsm.ClusterState().Joined() && r.node.raft.State() == raft.Leader
	})
}

// joined waits until the cluster's configuration names count members.
func (c *liveCluster) joined(count int) {
	c.t.Helper()
	eventually(c.t, 10*time.Second, fmt.Sprintf("%d members in the cluster", count), func() bool {
		leader := c.leader()
		return leader != nil && len(c.members(leader)) == count
	})
}

// noClusterStarts asserts no cluster after ticks enough for every replica to
// have tried.
func (c *liveCluster) noClusterStarts() {
	c.t.Helper()
	time.Sleep(20 * testTiming.Tick)
	for _, r := range c.replicas {
		if r.node.fsm.ClusterState().Joined() {
			c.t.Fatalf("replica %s started a cluster", r.node.member)
		}
	}
}

// serverFor is the member's place in the cluster's configuration, where it
// has one: a member that moves leaves the configuration and comes back.
func (c *liveCluster) serverFor(leader *liveReplica, member string) (raft.Server, bool) {
	future := leader.node.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return raft.Server{}, false
	}
	for _, server := range future.Configuration().Servers {
		if server.ID == raft.ServerID(member) {
			return server, true
		}
	}
	return raft.Server{}, false
}

// reaches waits until the cluster's configuration reaches r at address, as
// the member r is.
func (c *liveCluster) reaches(leader, r *liveReplica, address netip.AddrPort) {
	c.t.Helper()
	eventually(c.t, 15*time.Second, fmt.Sprintf("the cluster reaching member %s at %s", r.node.member, address), func() bool {
		server, named := c.serverFor(leader, string(r.node.member))
		return named && server.Address == raftAddressOf(address, r)
	})
}

// raftAddressOf is the Raft address of a member answering at an address.
func raftAddressOf(address netip.AddrPort, r *liveReplica) raft.ServerAddress {
	return raftAddr{
		endpoint: address,
		member:   string(r.node.member),
	}.serverAddress()
}

// addVoter adds r to the configuration the leader holds.
func (c *liveCluster) addVoter(leader, r *liveReplica) {
	c.t.Helper()
	server := voter(r)
	if err := leader.node.raft.AddVoter(server.ID, server.Address, 0, 0).Error(); err != nil {
		c.t.Fatalf("add voter: %v", err)
	}
}

func voter(r *liveReplica) raft.Server {
	return raft.Server{
		Suffrage: raft.Voter,
		ID:       raft.ServerID(r.node.member),
		Address:  raft.ServerAddress(r.node.mux.Addr().String()),
	}
}

// decreeEntry is the log entry r logs for one of the operator's decrees.
func (c *liveCluster) decreeEntry(r *liveReplica, kind cdsdecree.Kind) *DecreeEntry {
	c.t.Helper()
	fixture := c.fixture(r)
	decree := fixture.decree(kind)
	if targeted(kind) {
		decree.TargetMember = string(r.node.member)
	}
	entry := fixture.entryFor(decree)
	return &entry
}

// fixture is the state machine of r as the decree fixtures hold it.
func (c *liveCluster) fixture(r *liveReplica) *replica {
	return &replica{
		FSM:     r.node.fsm,
		cluster: c.cluster,
		t:       c.t,
	}
}

// targeted names the decree kinds that name the replica they are for.
func targeted(kind cdsdecree.Kind) bool {
	switch kind {
	case cdsdecree.Genesis,
		cdsdecree.Recover,
		cdsdecree.Admit:
		return true
	}
	return false
}

// commitRaw bypasses the checks a replica makes before it proposes an entry.
func (c *liveCluster) commitRaw(leader *liveReplica, entry []byte) {
	c.t.Helper()
	if err := leader.node.raft.Apply(entry, testTiming.Apply).Error(); err != nil {
		c.t.Fatalf("commit %s: %v", entry, err)
	}
}

// settled waits until every replica joined and the leader's configuration names them all.
func (c *liveCluster) settled(within time.Duration) {
	c.t.Helper()
	eventually(c.t, within, "the cluster settled", func() bool {
		leader := c.leader()
		if leader == nil || len(c.members(leader)) != len(c.replicas) {
			return false
		}
		return slices.IndexFunc(c.replicas, func(r *liveReplica) bool {
			return !r.node.fsm.ClusterState().Joined()
		}) < 0
	})
}

// leader is the replica the cluster elected, or nil while it has none.
func (c *liveCluster) leader() *liveReplica {
	for _, r := range c.replicas {
		if r.node.raft.State() == raft.Leader {
			return r
		}
	}
	return nil
}

// follower is any replica the cluster did not elect.
func (c *liveCluster) follower() *liveReplica {
	for _, r := range c.replicas {
		if r.node.raft.State() != raft.Leader {
			return r
		}
	}
	return nil
}

// members are the member ids the leader's configuration names.
func (c *liveCluster) members(leader *liveReplica) []raft.ServerID {
	future := leader.node.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return nil
	}
	var members []raft.ServerID
	for _, server := range future.Configuration().Servers {
		members = append(members, server.ID)
	}
	return members
}

// verifiesAgain is the reply that puts a stub's verdict back.
var verifiesAgain = mockapi.ErrorReply{}

// partition cuts r off from its peers, in both directions.
func (c *liveCluster) partition(r *liveReplica, cut bool) {
	c.t.Helper()
	if !cut {
		r.stub.SetVerifyError(verifiesAgain)
		return
	}
	r.stub.SetVerifyError(mockapi.VerificationFailed("the network is cut"))
	closePeerConnections(r.node.mux)
}

// closePeerConnections closes every attested connection a replica holds.
func closePeerConnections(m *mux) {
	m.mu.Lock()
	open := slices.Collect(maps.Keys(m.peers))
	m.mu.Unlock()
	for _, connection := range open {
		connection.Close()
	}
}

// relay carries every connection to a replica's own peer port, as the host's
// routing does; several replicas behind one answer there in turn.
type relay struct {
	listener net.Listener
	cutAfter time.Duration

	mu      sync.Mutex
	to      []netip.AddrPort
	carried int
}

// newRelay carries connections to the replicas given, one after the other.
func newRelay(t *testing.T, cutAfter time.Duration, to ...netip.AddrPort) *relay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &relay{
		listener: listener,
		cutAfter: cutAfter,
		to:       to,
	}
	go r.serve()
	t.Cleanup(r.close)
	return r
}

func (r *relay) address() netip.AddrPort {
	return r.listener.Addr().(*net.TCPAddr).AddrPort()
}

func (r *relay) close() {
	r.listener.Close()
}

func (r *relay) serve() {
	for {
		accepted, err := r.listener.Accept()
		if err != nil {
			return
		}
		go r.carry(accepted)
	}
}

// carry splices one connection to the next replica behind the relay.
func (r *relay) carry(accepted net.Conn) {
	defer accepted.Close()
	onward, err := net.Dial("tcp", r.next().String())
	if err != nil {
		return
	}
	defer onward.Close()
	if r.cutAfter > 0 {
		deadline := time.Now().Add(r.cutAfter)
		_ = accepted.SetDeadline(deadline)
		_ = onward.SetDeadline(deadline)
	}
	go func() { _, _ = io.Copy(onward, accepted) }()
	_, _ = io.Copy(accepted, onward)
}

// next is the replica the next connection goes to.
func (r *relay) next() netip.AddrPort {
	r.mu.Lock()
	defer r.mu.Unlock()
	to := r.to[r.carried%len(r.to)]
	r.carried++
	return to
}

// caughtUp waits until r has applied every entry leader has applied.
func (c *liveCluster) caughtUp(r *liveReplica, leader *liveReplica, within time.Duration) {
	c.t.Helper()
	applied := leader.node.fsm.AppliedIndex()
	eventually(c.t, within, fmt.Sprintf("replica %s applied index %d", r.node.member, applied), func() bool {
		return r.node.fsm.AppliedIndex() >= applied
	})
}

func eventually(t *testing.T, within time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// testWorkload is a one-container workload; digest tells one from the next.
func testWorkload(t *testing.T, digest int) pkgallowlist.Workload {
	t.Helper()
	parsed, err := types.ParseDigest(fmt.Sprintf("sha256:%064x", digest))
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: parsed}}}
}
