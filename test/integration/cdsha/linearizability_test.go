//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	// writerClients write and read the allowlist at once, each through any
	// replica it picks per request.
	writerClients = 3
	// exerciseFor is how long they run, a third of it before the leader is
	// killed; pauseAfterRefusal keeps a refused client from flooding the
	// history with writes of unknown outcome while the cluster elects.
	exerciseFor       = 15 * time.Second
	pauseAfterRefusal = 100 * time.Millisecond
	checkFor          = 2 * time.Minute
)

// allowlistOp is one request a client sent: a write of the document admitting
// only workload, or a read of the one workload the served document admits.
type allowlistOp struct {
	write    bool
	workload string
}

// allowlistRegister models the allowlist as one register. A write replaces the
// whole document and every written workload is unique, so a history passes
// exactly when each read returns the workload of the last write ordered before
// it.
var allowlistRegister = porcupine.Model{
	Init: func() any { return seededWorkload },
	Step: func(state, input, output any) (bool, any) {
		op := input.(allowlistOp)
		if op.write {
			return true, op.workload
		}
		return output.(string) == state.(string), state
	},
	DescribeOperation: func(input, output any) string {
		op := input.(allowlistOp)
		if op.write {
			return "write " + op.workload
		}
		return "read " + output.(string)
	},
}

// Operators write and read the allowlist through every replica at once while
// the leader is killed, and the history they saw is checked against one
// register. A replica answering from state behind a write the cluster already
// confirmed, such as a revoked entry, or two replicas ordering writes
// differently, makes it illegal.
func TestTheAllowlistIsLinearizableAcrossALeaderLoss(t *testing.T) {
	c := newCluster(t, threeReplicas)
	leading := c.waitLeader(30 * time.Second)
	h := &history{start: time.Now()}
	var reachable atomic.Pointer[[]*replica]
	reachable.Store(&c.replicas)

	stop := make(chan struct{})
	var clients sync.WaitGroup
	for client := range writerClients {
		clients.Go(func() { c.exercise(h, client, &reachable, stop) })
	}
	time.Sleep(exerciseFor / 3)
	c.kill(leading)
	others := c.others(leading)
	reachable.Store(&others)
	lost := h.now()
	time.Sleep(exerciseFor - exerciseFor/3)
	close(stop)
	clients.Wait()

	operations, unseen := withoutUnseenWrites(h.operations())
	t.Logf("dropped %d writes of unknown outcome that no read returned", unseen)
	requireTrafficAfter(t, operations, lost)
	result, info := porcupine.CheckOperationsVerbose(allowlistRegister, operations, checkFor)
	switch result {
	case porcupine.Ok:
		return
	case porcupine.Unknown:
		t.Fatalf("the checker found no verdict on %d operations within %s", len(operations), checkFor)
	}
	path := filepath.Join(t.TempDir(), "history.html")
	if err := porcupine.VisualizePath(allowlistRegister, info, path); err != nil {
		t.Logf("no visualization: %v", err)
	}
	t.Fatalf("the check of %d operations answered %s; the history is in %s", len(operations), result, path)
}

// exercise sends one client's requests until stop closes, each to a replica it
// picks from those not killed. A write the cluster did not confirm may still
// have taken effect, so its history entry never returns.
func (c *cluster) exercise(
	h *history,
	client int,
	reachable *atomic.Pointer[[]*replica],
	stop <-chan struct{},
) {
	for n := 0; ; n++ {
		select {
		case <-stop:
			return
		default:
		}
		replicas := *reachable.Load()
		r := replicas[rand.IntN(len(replicas))]
		answered := false
		if n%2 == 0 {
			answered = c.writeOnce(h, client, r, fmt.Sprintf("client-%d-write-%d", client, n))
		} else {
			answered = c.readOnce(h, client, r)
		}
		if !answered {
			time.Sleep(pauseAfterRefusal)
		}
	}
}

func (c *cluster) writeOnce(h *history, client int, r *replica, workload string) bool {
	call := h.now()
	code, _ := c.attempt(r, http.MethodPut, "/allowlist", allowlistDocument(workload), c.signer)
	returned := int64(math.MaxInt64)
	if code == http.StatusNoContent {
		returned = h.now()
	}
	h.add(porcupine.Operation{
		ClientId: client,
		Input:    allowlistOp{write: true, workload: workload},
		Call:     call,
		Return:   returned,
	})
	return code == http.StatusNoContent
}

// readOnce records a read the replica answered; a refused read observed
// nothing, so it leaves no entry.
func (c *cluster) readOnce(h *history, client int, r *replica) bool {
	call := h.now()
	code, body := c.attempt(r, http.MethodGet, "/allowlist", nil, nil)
	returned := h.now()
	if code != http.StatusOK {
		return false
	}
	workload, ok := onlyWorkload(body)
	if !ok {
		c.t.Errorf("replica %d served an allowlist admitting other than one workload: %s", r.index, body)
		return false
	}
	h.add(porcupine.Operation{
		ClientId: client,
		Input:    allowlistOp{},
		Call:     call,
		Output:   workload,
		Return:   returned,
	})
	return true
}

// onlyWorkload is the one workload a served allowlist admits.
func onlyWorkload(document []byte) (string, bool) {
	var served struct {
		Workloads map[string]json.RawMessage `json:"workloads"`
	}
	if json.Unmarshal(document, &served) != nil || len(served.Workloads) != 1 {
		return "", false
	}
	for workload := range served.Workloads {
		return workload, true
	}
	return "", false
}

// withoutUnseenWrites drops each write of unknown outcome whose workload no
// read returned. Ordering such a write after every other operation is always
// legal for a register, so dropping it changes no verdict, and it spares the
// checker a write it could otherwise place anywhere.
func withoutUnseenWrites(operations []porcupine.Operation) ([]porcupine.Operation, int) {
	read := map[string]bool{}
	for _, op := range operations {
		if !op.Input.(allowlistOp).write {
			read[op.Output.(string)] = true
		}
	}
	kept := slices.DeleteFunc(slices.Clone(operations), func(op porcupine.Operation) bool {
		in := op.Input.(allowlistOp)
		return in.write && op.Return == math.MaxInt64 && !read[in.workload]
	})
	return kept, len(operations) - len(kept)
}

// requireTrafficAfter fails a run whose clients confirmed no write or answered
// no read after the leader was lost, since its check would prove nothing
// about the loss.
func requireTrafficAfter(t *testing.T, operations []porcupine.Operation, lost int64) {
	t.Helper()
	var writes, reads int
	for _, op := range operations {
		if op.Call < lost || op.Return == math.MaxInt64 {
			continue
		}
		if op.Input.(allowlistOp).write {
			writes++
		} else {
			reads++
		}
	}
	if writes == 0 || reads == 0 {
		t.Fatalf("after the leader loss the cluster confirmed %d writes and answered %d reads, want both", writes, reads)
	}
	t.Logf("%d operations, of which %d confirmed writes and %d reads after the leader loss", len(operations), writes, reads)
}

// history collects the operations of every client, timed on one monotonic clock.
type history struct {
	start    time.Time
	mu       sync.Mutex
	recorded []porcupine.Operation
}

func (h *history) now() int64 {
	return time.Since(h.start).Nanoseconds()
}

func (h *history) add(op porcupine.Operation) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recorded = append(h.recorded, op)
}

func (h *history) operations() []porcupine.Operation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.recorded)
}

// attempt sends one request and reports noAnswer for any failure to reach the
// replica or read its whole answer, so it is safe off the test's goroutine.
func (c *cluster) attempt(
	r *replica,
	method string,
	route string,
	body []byte,
	operator *operatorauth.Signer,
) (int, []byte) {
	request, err := http.NewRequest(method, r.base+route, bytes.NewReader(body)) //nolint:noctx // the client carries the deadline
	if err != nil {
		return noAnswer, nil
	}
	if operator != nil {
		authorization, err := operator.Authorization(method, route, body)
		if err != nil {
			return noAnswer, nil
		}
		request.Header.Set("Authorization", authorization)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return noAnswer, nil
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer))
	if err != nil {
		return noAnswer, nil
	}
	return response.StatusCode, answer
}
