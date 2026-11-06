//go:build integration && linux

package metadataha

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/testutil/etcdtest"
)

type etcdProcesses struct {
	*etcdtest.Cluster
	t *testing.T
}

func newEtcdProcesses(t *testing.T) *etcdProcesses {
	t.Helper()
	return &etcdProcesses{Cluster: etcdtest.New(t), t: t}
}

func (p *etcdProcesses) backend() *Etcd {
	p.t.Helper()
	e, err := NewEtcd(EtcdConfig{Endpoints: p.URLs, ClusterID: p.ClusterID, TLS: p.TLS})
	if err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(e.Close)
	return e
}

func TestEtcdQuorumTransactions(t *testing.T) {
	p := newEtcdProcesses(t)
	e := p.backend()
	ctx := context.Background()
	key := strings.Repeat("a", 64)
	create := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: key}}, Writes: []metadatapilot.Record{{Key: key, Version: "0000000000000001", Value: []byte("ciphertext-1")}}}
	var won, conflict atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			err := e.Commit(ctx, "cluster-a", create)
			if err == nil {
				won.Add(1)
			} else if errors.Is(err, objectwal.ErrConflict) {
				conflict.Add(1)
			} else {
				t.Errorf("CAS: %v", err)
			}
		})
	}
	wg.Wait()
	if won.Load() != 1 || conflict.Load() != 15 {
		t.Fatalf("CAS winners=%d conflicts=%d", won.Load(), conflict.Load())
	}
	read := func() error {
		rows, err := e.Read(ctx, "cluster-a", []string{key})
		if err == nil && (rows[0].Version != "0000000000000001" || string(rows[0].Value) != "ciphertext-1") {
			return errors.New("acknowledged state changed")
		}
		return err
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	// A successful send whose reply is lost must never be resubmitted.
	lost := p.backend()
	if _, err := lost.Read(ctx, "cluster-a", []string{key}); err != nil {
		t.Fatal(err)
	}
	transport := lost.client.Transport
	t.Cleanup(transport.(*http.Transport).CloseIdleConnections)
	var sends atomic.Int32
	lost.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sends.Add(1)
		resp, err := transport.RoundTrip(r)
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, io.ErrUnexpectedEOF
	})
	ambiguous := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: strings.Repeat("b", 64)}}, Writes: []metadatapilot.Record{{Key: strings.Repeat("b", 64), Version: "0000000000000001", Value: []byte("lost-reply")}}}
	if err := lost.Commit(ctx, "cluster-a", ambiguous); !errors.Is(err, objectwal.ErrInDoubt) || sends.Load() != 1 {
		t.Fatalf("ambiguous commit: %v sends=%d", err, sends.Load())
	}
	rows, err := e.Read(ctx, "cluster-a", []string{ambiguous.Checks[0].Key})
	if err != nil || rows[0].Version != "0000000000000001" {
		t.Fatalf("lost reply did not leave exactly one commit: %v", err)
	}
	leader := -1
	for i := range 3 {
		s, err := p.Status(i)
		if err == nil && s.Header.MemberID == s.Leader {
			leader = i
		}
	}
	if leader < 0 {
		t.Fatal("no leader")
	}
	p.Stop(leader)
	deadline := time.Now().Add(10 * time.Second)
	var available bool
	for time.Now().Before(deadline) {
		if read() == nil {
			available = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !available {
		t.Fatal("majority did not retain acknowledged state after leader crash")
	}
	second := (leader + 1) % 3
	p.Stop(second)
	ctxMinority, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := e.Read(ctxMinority, "cluster-a", []string{key}); err == nil {
		t.Fatal("minority served a purportedly current read")
	}
	writeMinority, stopMinority := context.WithTimeout(ctx, 3*time.Second)
	defer stopMinority()
	if err := e.Commit(writeMinority, "cluster-a", ambiguous); err == nil || errors.Is(err, objectwal.ErrConflict) {
		t.Fatal("minority claimed a successful or definite conditional commit")
	}
	p.Start(second)
	deadline = time.Now().Add(10 * time.Second)
	available = false
	for time.Now().Before(deadline) {
		if read() == nil {
			available = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !available {
		t.Fatal("restored quorum did not retain acknowledged state")
	}
	wrong := p.backend()
	wrong.clusterID = "1"
	if _, err := wrong.Read(ctx, "cluster-a", []string{key}); !errors.Is(err, objectwal.ErrCorrupt) {
		t.Fatal("foreign metadata cluster accepted")
	}
	foreignKey := strings.Repeat("e", 64)
	foreignTxn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: foreignKey}}, Writes: []metadatapilot.Record{{Key: foreignKey, Version: "0000000000000001", Value: []byte("must-not-write")}}}
	if err := wrong.Commit(ctx, "cluster-a", foreignTxn); err == nil {
		t.Fatal("foreign cluster accepted a commit")
	}
	rows, err = e.Read(ctx, "cluster-a", []string{foreignKey})
	if err != nil || rows[0].Version != "" {
		t.Fatal("identity was checked only after mutating a foreign cluster")
	}
	t.Log("three real members: one CAS winner, ambiguous commit sent once, leader crash recovery, minority fail-closed, quorum restoration, cluster pin")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEtcdAtomicReadSet(t *testing.T) {
	p := newEtcdProcesses(t)
	e := p.backend()
	ctx := context.Background()
	a, b := strings.Repeat("c", 64), strings.Repeat("d", 64)
	var done atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		defer done.Store(true)
		version := ""
		for i := range 64 {
			next, _ := metadatapilot.NextVersion(version)
			txn := metadatapilot.Transaction{Checks: []metadatapilot.Check{{Key: a, Version: version}, {Key: b, Version: version}}, Writes: []metadatapilot.Record{{Key: a, Version: next, Value: []byte{byte(i + 1)}}, {Key: b, Version: next, Value: []byte{byte(i + 1)}}}}
			if err := e.Commit(ctx, "atomic", txn); err != nil {
				t.Error(err)
				return
			}
			version = next
		}
	})
	for range 8 {
		wg.Go(func() {
			last := ""
			for !done.Load() {
				rows, err := e.Read(ctx, "atomic", []string{a, b})
				if err != nil {
					t.Error(err)
					return
				}
				if rows[0].Version != rows[1].Version || !bytes.Equal(rows[0].Value, rows[1].Value) || rows[0].Version < last {
					t.Error("torn or regressing current snapshot")
					return
				}
				last = rows[0].Version
			}
		})
	}
	wg.Wait()
	rows, err := e.Read(ctx, "atomic", []string{a, b})
	if err != nil || rows[0].Version != "0000000000000040" {
		t.Fatalf("final pair: %v", err)
	}
}
