package cdsha

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A client's write at a replica that does not lead is committed by the leader
// and answered once the replica that took it has applied it too, so the
// client's next read at that replica sees its own write.
func TestAWriteAtAFollowerIsCommittedByTheLeader(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()

	stored, held, err := follower.node.Secrets().PutIfAbsent(t.Context(), "/web/token", []byte("secret"), secrets.WorkloadHolder("web"))
	if err != nil || string(stored) != "secret" || held.Exists {
		t.Fatalf("a write at a follower stored %q over held %+v: %v", stored, held, err)
	}

	if value, err := follower.node.Secrets().Get(t.Context(), "/web/token"); err != nil || string(value) != "secret" {
		t.Fatalf("the replica that took the write holds %q: %v", value, err)
	}
	if value, err := c.leader().node.Secrets().Get(t.Context(), "/web/token"); err != nil || string(value) != "secret" {
		t.Fatalf("the leader holds %q: %v", value, err)
	}
	if _, _, err := follower.node.Allowlist().SeedWorkloads(map[string]pkgallowlist.Workload{"web": testWorkload(t, 1)}); err != nil {
		t.Fatalf("an allowlist write at a follower: %v", err)
	}
	if !follower.node.Bindings().Record("sandbox-1", "10.0.0.1") {
		t.Fatal("the ledger refused a binding at a follower")
	}
}

// A write a replica forwards is applied at the leader's clock: binding expiry
// and the allowlist's journal time are the cluster's one clock, as the single
// CDS they replace followed its own.
func TestAForwardedWriteAppliesAtTheLeadersClock(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	// A replica whose clock is far behind forwards a binding stamped with it.
	// Under that clock the binding is long expired.
	stamped := Entry{
		Kind: KindBinding,
		Binding: &sandboxledger.Command{
			SandboxID: "sandbox-1",
			Host:      "10.0.0.1",
			AtMS:      1,
		},
	}

	answer := leader.node.answerControl(peer{member: "member-a"}, writeRequest(t, stamped))

	if answer.Err != "" {
		t.Fatalf("a forwarded binding was refused: %s", answer.Err)
	}
	if host, bound := leader.node.Bindings().Lookup("sandbox-1"); !bound || host != "10.0.0.1" {
		t.Fatalf("the committed binding is %q, %v: it did not apply at the leader's clock", host, bound)
	}
}

// The leader commits only the client writes replicas forward, and refuses
// everything else before it reaches the log: an entry no replica can apply
// would stop them all, and decrees, doubts and format changes are the
// leader's own. Nothing it refuses reaches the log.
func TestTheLeaderCommitsOnlyForwardedClientWrites(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	put := &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}
	for name, forwarded := range map[string]json.RawMessage{
		"not an entry":                json.RawMessage(`"x"`),
		"not an object":               json.RawMessage(`[1]`),
		"a field the entry has not":   json.RawMessage(`{"kind":"secret","secret":{"op":"put","path":"/p","value":"dg=="},"from_the_future":1}`),
		"a kind the entry has not":    json.RawMessage(`{"kind":"from-the-future"}`),
		"a format change":             marshalled(t, Entry{Kind: KindFormat, SetFormat: Format}),
		"a decree":                    marshalled(t, Entry{Kind: KindDecree, Decree: &DecreeEntry{}}),
		"a doubt":                     marshalled(t, Entry{Kind: KindDoubt}),
		"no command":                  marshalled(t, Entry{Kind: KindSecret}),
		"two commands":                marshalled(t, Entry{Kind: KindSecret, Secret: put, Binding: &sandboxledger.Command{SandboxID: "sandbox-1"}}),
		"a client kind with a decree": marshalled(t, Entry{Kind: KindSecret, Secret: put, Decree: &DecreeEntry{}}),
		"an entry of its own format":  marshalled(t, Entry{Kind: KindSecret, Format: Format, Secret: put}),
	} {
		t.Run(name, func(t *testing.T) {
			answer := leader.node.answerControl(
				peer{member: "member-a"},
				controlRequest{
					Op:    opWrite,
					Entry: forwarded,
				},
			)

			if answer.Err == "" {
				t.Fatalf("the leader committed it: %+v", answer)
			}
			// An entry the leader commits is answered with the index it
			// committed at, so a refusal naming none reached no log.
			if answer.Index != 0 {
				t.Fatalf("the leader refused the entry at index %d", answer.Index)
			}
			if stuck := leader.node.fsm.Stuck(); stuck != "" {
				t.Fatalf("the leader stopped following the log: %s", stuck)
			}
		})
	}
	if _, err := leader.node.Secrets().Get(t.Context(), put.Path); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("the secret a refused entry carried is in the cluster's state: %v", err)
	}
}

// A replica that does not lead refuses a forwarded write and names the leader
// it follows, so the replica that took the write asks it instead.
func TestAForwardedWriteToAFollowerNamesTheLeader(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()
	put := &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}

	answer := follower.node.answerControl(peer{member: "member-a"}, writeRequest(t, Entry{Kind: KindSecret, Secret: put}))

	if answer.Err == "" {
		t.Fatal("a replica that does not lead committed a forwarded write")
	}
	if answer.Leader != string(c.leader().node.member) {
		t.Fatalf("the follower named leader %q, the cluster elected %q", answer.Leader, c.leader().node.member)
	}
}

// A write the leader's admission cap refused is the store's full error at the
// replica that took it, which clears as the replicated state shrinks, and not
// one to try again.
func TestAForwardedWriteTheCapRefusedIsFullNotUnavailable(t *testing.T) {
	reason := "the replicated state is at its capacity"

	full := secretsErrors.uncommitted(refusedByLeader(controlAnswer{Err: reason, Full: true}))

	if !errors.Is(full, secrets.ErrCapacity) || errors.Is(full, secrets.ErrUnavailable) {
		t.Fatalf("a forwarded write over the cap answered %v", full)
	}
	if !strings.Contains(full.Error(), reason) {
		t.Fatalf("the refusal does not carry what the leader answered: %v", full)
	}
	unavailable := secretsErrors.uncommitted(refusedByLeader(controlAnswer{Err: "this replica does not lead the cluster"}))
	if !errors.Is(unavailable, secrets.ErrUnavailable) || errors.Is(unavailable, secrets.ErrCapacity) {
		t.Fatalf("a forwarded write the cluster could not commit answered %v", unavailable)
	}
}

func writeRequest(t *testing.T, entry Entry) controlRequest {
	t.Helper()
	return controlRequest{Op: opWrite, Entry: marshalled(t, entry)}
}

func marshalled(t *testing.T, entry Entry) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
