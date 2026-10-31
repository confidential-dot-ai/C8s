// Raft's transport over the attested peer port, with two departures from
// Raft's defaults.
//
// Pipelining is off (MaxRPCsInFlight 1 is Raft's documented switch): the v1.8
// pipeline deadlocks once a follower stops answering, because its response
// decoder quits on the first failure while the transport still hands it
// results, and the sender then waits on the transport for good.
//
// A heartbeat takes Raft's fast path only when it cannot change this
// replica's term or role. One that steps a leader or a candidate down there
// runs concurrently with the main loop, which may be stamping a client write
// with the term the heartbeat just ended, so that two replicas write
// different entries at one index and term (hashicorp/raft#695, open in
// v1.8.0).

package cdsha

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
)

func peerTransportConfig(stream raft.StreamLayer, logger hclog.Logger) *raft.NetworkTransportConfig {
	return &raft.NetworkTransportConfig{
		Stream:          stream,
		MaxPool:         pooledPeerConnections,
		MaxRPCsInFlight: noPipelining,
		Timeout:         peerRPCTimeout,
		Logger:          logger,
	}
}

const (
	// noPipelining leaves Raft replicating one AppendEntries at a time.
	noPipelining = 1
	// pooledPeerConnections are kept per peer, each an attested handshake the
	// transport need not make again.
	pooledPeerConnections = 3
	// peerRPCTimeout bounds one Raft RPC to a peer that does not answer.
	peerRPCTimeout = 10 * time.Second
)

// termSafeHeartbeats sends every heartbeat that could change this replica's
// term or role to the main loop, and leaves the rest on Raft's fast path, so
// a replica whose main loop is busy applying keeps its leader.
type termSafeHeartbeats struct {
	*raft.NetworkTransport
	// Until raft is set, every heartbeat goes to the main loop.
	raft     atomic.Pointer[raft.Raft]
	consumer chan raft.RPC
	done     chan struct{}
	stop     sync.Once
}

func newTermSafeHeartbeats(transport *raft.NetworkTransport) *termSafeHeartbeats {
	t := &termSafeHeartbeats{
		NetworkTransport: transport,
		consumer:         make(chan raft.RPC),
		done:             make(chan struct{}),
	}
	go t.forward(transport.Consumer())
	return t
}

// follows names the instance whose term and role decide a heartbeat's path.
func (t *termSafeHeartbeats) follows(r *raft.Raft) {
	t.raft.Store(r)
}

// forward carries the transport's RPCs to the main loop's channel, which the
// redirected heartbeats share.
func (t *termSafeHeartbeats) forward(rpcs <-chan raft.RPC) {
	for {
		select {
		case rpc := <-rpcs:
			select {
			case t.consumer <- rpc:
			case <-t.done:
				rpc.Respond(nil, raft.ErrTransportShutdown)
				return
			}
		case <-t.done:
			return
		}
	}
}

// Consumer carries the transport's RPCs and the heartbeats the fast path
// must not take.
func (t *termSafeHeartbeats) Consumer() <-chan raft.RPC {
	return t.consumer
}

// SetHeartbeatHandler installs Raft's fast path behind the term check.
func (t *termSafeHeartbeats) SetHeartbeatHandler(fast func(raft.RPC)) {
	t.NetworkTransport.SetHeartbeatHandler(func(rpc raft.RPC) { t.heartbeat(fast, rpc) })
}

func (t *termSafeHeartbeats) heartbeat(fast func(raft.RPC), rpc raft.RPC) {
	if t.termSafe(rpc) {
		fast(rpc)
		return
	}
	select {
	case t.consumer <- rpc:
	case <-t.done:
		rpc.Respond(nil, raft.ErrTransportShutdown)
	}
}

// termSafe reports a heartbeat the fast path may answer: one for a follower
// at a term no newer than its own.
func (t *termSafeHeartbeats) termSafe(rpc raft.RPC) bool {
	heartbeat, ok := rpc.Command.(*raft.AppendEntriesRequest)
	if !ok {
		return false
	}
	r := t.raft.Load()
	return r != nil && r.State() == raft.Follower && heartbeat.Term <= r.CurrentTerm()
}

// Close stops the forwarding and closes the transport, the peer port with it.
func (t *termSafeHeartbeats) Close() error {
	t.stop.Do(func() { close(t.done) })
	return t.NetworkTransport.Close()
}

// peerPortOnLoan is the peer transport as one Raft instance holds it. Raft
// closes the transport it was given when it shuts down, and this process's
// peer port carries the control channel and whatever Raft it runs next: a
// replica that carried its cluster on alone runs a second one (recover.go).
type peerPortOnLoan struct {
	*termSafeHeartbeats
}

// Close leaves the port open: the process that lent it closes it (Node.stop).
func (peerPortOnLoan) Close() error {
	return nil
}
