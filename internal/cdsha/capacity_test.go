package cdsha

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The parts of a snapshot divide the one limit between them, and a growing
// write may fill only part of a bound, so a replica that holds a full state
// can still take one more copy of it.
func TestTheStateBoundsDivideTheOneLimit(t *testing.T) {
	b := stateBounds()
	if b.header+b.image != MaxStateBytes || b.stream != MaxStateBytes {
		t.Fatalf("a header of %d, an image of %d and a stream of %d divide a limit of %d", b.header, b.image, b.stream, MaxStateBytes)
	}
	for _, bound := range []int64{b.header, b.image} {
		if admitted(bound) >= bound {
			t.Fatalf("a write may fill %d of a bound of %d, leaving no room", admitted(bound), bound)
		}
	}
}

// A replica refuses a write that would grow the state past what it can hand
// a joining replica, and says what the operator can do about it.
func TestAWriteThatOutgrowsTheStateLimitIsRefused(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	write := Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:        allowlist.OpReplaceAll,
			AtMS:      time.Now().UnixMilli(),
			Allowlist: &pkgallowlist.Allowlist{},
		},
	}

	if err := r.Admit(rawOf(t, write)); err != nil {
		t.Fatalf("a write to an empty cluster: %v", err)
	}
	err := r.admit(
		bounds{
			header: 1 << 20,
			image:  1 << 10,
		},
		write,
		1<<20,
	)
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("a write past the cap = %v, want ErrCapacity", err)
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("the refusal does not name what grew: %v", err)
	}
}

// A secret write grows the state a snapshot carries in its header, and is
// judged against that part of the limit.
func TestASecretWriteIsJudgedOnTheSnapshotHeader(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	write := Entry{
		Kind: KindSecret,
		Secret: &secrets.Command{
			Op:    secrets.OpPut,
			Path:  "/db/password",
			Value: []byte("hunter2"),
		},
	}

	underTheCap := bounds{
		header: 1 << 20,
		image:  1 << 10,
	}
	if err := r.admit(underTheCap, write, 1<<10); err != nil {
		t.Fatalf("a secret write under the header cap: %v", err)
	}
	pastTheCap := bounds{
		header: 1 << 10,
		image:  1 << 20,
	}
	if err := r.admit(pastTheCap, write, 1<<20); !errors.Is(err, ErrCapacity) {
		t.Fatalf("a secret write past the header cap = %v, want ErrCapacity", err)
	}
}

// The cap never refuses the writes a cluster at the cap needs: the ones that
// make room, the startup work a replica cannot skip, and what the cluster's
// own policy already bounds.
func TestTheCapNeverRefusesTheWritesThatMakeRoom(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	at := time.Now().UnixMilli()
	for name, e := range map[string]Entry{
		"a token spend": {
			Kind: KindAllowlist,
			Allowlist: &allowlist.Command{
				Op:    allowlist.OpConsumeToken,
				AtMS:  at,
				Token: "token",
			},
		},
		"a history prune": {
			Kind: KindAllowlist,
			Allowlist: &allowlist.Command{
				Op:   allowlist.OpPruneHistory,
				AtMS: at,
				Keep: 1,
			},
		},
		"a seed": {
			Kind: KindAllowlist,
			Allowlist: &allowlist.Command{
				Op:   allowlist.OpSeed,
				AtMS: at,
			},
		},
		"a journal start": {
			Kind: KindAllowlist,
			Allowlist: &allowlist.Command{
				Op:   allowlist.OpStartJournal,
				AtMS: at,
			},
		},
		"a binding": {
			Kind: KindBinding,
			Binding: &sandboxledger.Command{
				SandboxID: "sandbox",
				Host:      "10.0.0.7:9000",
				AtMS:      at,
			},
		},
		"a decree": {Kind: KindDecree, Decree: &DecreeEntry{}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := r.admit(bounds{}, e, 1<<30); err != nil {
				t.Fatalf("%s at the cap = %v", name, err)
			}
		})
	}
}

// The cap is a safety net, not a gate on availability: a replica that cannot
// read the size of its own state refuses no write for it.
func TestAStateWhoseSizeCannotBeReadRefusesNoWrite(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	if err := r.al.Close(); err != nil {
		t.Fatal(err)
	}
	write := Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:        allowlist.OpReplaceAll,
			AtMS:      time.Now().UnixMilli(),
			Allowlist: &pkgallowlist.Allowlist{},
		},
	}
	if err := r.admit(bounds{}, write, 1<<30); err != nil {
		t.Fatalf("a write a closed store cannot be measured for = %v", err)
	}
}
