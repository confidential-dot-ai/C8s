//go:build linux

package snpaccept

import (
	"bytes"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
)

func batchRequests() []TDXCustodyRequest {
	var out []TDXCustodyRequest
	for i := byte(1); i <= 3; i++ {
		out = append(out, TDXCustodyRequest{Recipient: CustodyRequest{
			Family: "tdx", Nonce: bytes.Repeat([]byte{i}, overenc.SessionIDBytes),
			PublicKey: bytes.Repeat([]byte{i}, overenc.XWingEKBytes), Report: []byte{i},
		}, Collateral: IntelCollateral{"public": {Body: []byte{i}}}})
	}
	return out
}

func TestBatchCustodyIsBoundedDistinctAndPhaseSpecific(t *testing.T) {
	q := Request{Operation: "delegate-three", Custodies: batchRequests()}
	if !validSNPPhase(q) {
		t.Fatal("bounded batch rejected")
	}
	for _, op := range []string{"enroll", "delegate", "copy", "seed", "recover"} {
		bad := q
		bad.Operation = op
		if validSNPPhase(bad) {
			t.Fatalf("batch smuggled into %s", op)
		}
	}
	for _, change := range []func(*Request){
		func(q *Request) { q.Custodies = q.Custodies[:2] },
		func(q *Request) { q.Custodies = append(q.Custodies, q.Custodies[0]) },
		func(q *Request) { q.Custodies[1].Recipient.PublicKey = q.Custodies[0].Recipient.PublicKey },
		func(q *Request) { q.Custodies[1].Recipient.Nonce = q.Custodies[0].Recipient.Nonce },
		func(q *Request) { q.Custodies[0].Recipient.Family = "snp" },
		func(q *Request) { q.Custodies[0].Collateral = nil },
		func(q *Request) { q.Custody = &CustodyRequest{} },
		func(q *Request) { q.OperatorKey = []byte{1} },
	} {
		bad := Request{Operation: "delegate-three", Custodies: batchRequests()}
		change(&bad)
		if validSNPPhase(bad) {
			t.Fatal("unbounded, repeated, or mixed request accepted")
		}
	}
}

func TestBatchCustodyDoesNotReturnPartialReleaseOrRetry(t *testing.T) {
	for failed := 0; failed < 3; failed++ {
		calls := 0
		grants, err := delegateThree(batchRequests(), func(TDXCustodyRequest) (*CustodyGrant, error) {
			i := calls
			calls++
			if i == failed {
				return nil, errors.New("quote verification failed")
			}
			return &CustodyGrant{KEM: []byte{1}}, nil
		})
		if err == nil || grants != nil || calls != failed+1 {
			t.Fatal("partial grant exposed or failed delegation retried")
		}
	}
	calls := 0
	grants, err := delegateThree(batchRequests(), func(r TDXCustodyRequest) (*CustodyGrant, error) {
		calls++
		return &CustodyGrant{KEM: r.Recipient.Nonce}, nil
	})
	if err != nil || len(grants) != 3 || calls != 3 {
		t.Fatal("complete batch not returned once")
	}
}
