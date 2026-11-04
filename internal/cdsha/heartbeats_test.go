package cdsha

import (
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// The heartbeat fast path takes only the heartbeats that cannot change this
// replica's term or role; the rest go to the main loop, which answers them.
func TestOnlyATermSafeHeartbeatTakesTheFastPath(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	follower := c.follower()
	if leader.node.transport.termSafe(heartbeatAt(leader.node.raft.CurrentTerm(), nil)) {
		t.Fatal("a leader's heartbeat took the fast path")
	}
	term := follower.node.raft.CurrentTerm()
	fast := make(chan raft.RPC, 1)
	follower.node.transport.heartbeat(func(rpc raft.RPC) { fast <- rpc }, heartbeatAt(term, nil))
	select {
	case <-fast:
	default:
		t.Fatal("a follower's heartbeat at its own term did not take the fast path")
	}
	answered := make(chan raft.RPCResponse, 1)
	follower.node.transport.heartbeat(
		func(raft.RPC) { t.Error("a heartbeat of a newer term took the fast path") },
		heartbeatAt(term+1, answered))
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("the main loop did not answer a heartbeat of a newer term")
	}
}

func heartbeatAt(term uint64, answered chan raft.RPCResponse) raft.RPC {
	return raft.RPC{
		Command:  &raft.AppendEntriesRequest{Term: term},
		RespChan: answered,
	}
}

// The transport pipelines nothing: replication sends one AppendEntries at a
// time.
func TestThePeerTransportPipelinesNothing(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	_, err := r.node.transport.AppendEntriesPipeline(raft.ServerID(r.node.member), raft.ServerAddress(r.node.mux.Addr().String()))
	if !errors.Is(err, raft.ErrPipelineReplicationNotSupported) {
		t.Fatalf("the transport answered a pipeline: %v", err)
	}
}
