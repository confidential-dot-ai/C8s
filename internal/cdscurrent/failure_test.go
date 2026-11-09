package cdscurrent_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/casregister"
	"github.com/confidential-dot-ai/c8s/internal/cdscurrent"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type captureFailureRegister struct {
	cdscurrent.Register
	injected atomic.Int64
}

func (r *captureFailureRegister) Update(
	ctx context.Context,
	transform func([]byte) ([]byte, error),
) ([]byte, error) {
	return r.Register.Update(
		ctx,
		func(current []byte) ([]byte, error) {
			candidate, err := transform(current)
			if err != nil {
				return nil, err
			}
			// Inject a capture failure after the real handler spent its token and
			// changed its private view, but before the proposer can dispatch Accept.
			clear(candidate)
			r.injected.Add(1)
			return nil, cdscurrent.ErrCapacity
		},
	)
}

func TestUncommittedCapacityFailureDoesNotSpendOperatorToken(t *testing.T) {
	f := newFixture(
		t,
		testCluster,
	)
	replicas := f.start(
		testCluster,
		true,
	)
	oldPolicy := policy(
		t,
		"acknowledged-before-failure",
		false,
	)
	requireStatus(
		t,
		request(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			oldPolicy,
			f.authorization(
				"/allowlist",
				oldPolicy,
			),
			"",
		),
		http.StatusNoContent,
	)
	proposer, err := casregister.NewProposer(
		f.peers(),
		testCluster,
		16,
	)
	if err != nil {
		t.Fatal(err)
	}
	f.proposers = append(
		f.proposers,
		proposer,
	)
	fault := &captureFailureRegister{Register: proposer}
	failing, err := cdscurrent.New(
		fault,
		f.policies[testCluster],
	)
	if err != nil {
		t.Fatal(err)
	}
	f.replicas = append(
		f.replicas,
		failing,
	)
	newPolicy := policy(
		t,
		"must-remain-uncommitted",
		false,
	)
	token := f.authorization(
		"/allowlist",
		newPolicy,
	)
	response := request(
		failing,
		http.MethodPut,
		"/allowlist",
		newPolicy,
		token,
		"",
	)
	requireStatus(
		t,
		response,
		http.StatusServiceUnavailable,
	)
	if response.Header().Get("X-CDS-Outcome") != "" {
		t.Fatal("pre-acceptance capture failure was reported as an unknown commit")
	}
	if fault.injected.Load() != 1 {
		t.Fatal("test did not inject exactly one failure after application execution")
	}

	f.loseCompute()
	f.restartAuthorities()
	replicas = f.start(
		testCluster,
		false,
	)
	response = request(
		replicas[1],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
		"",
	)
	requireStatus(
		t,
		response,
		http.StatusOK,
	)
	marker, err := policyMarker(response.Body.Bytes())
	if err != nil || marker != "acknowledged-before-failure" {
		t.Fatalf(
			"uncommitted candidate survived recovery: marker %q, error %v",
			marker,
			err,
		)
	}
	assertLiveToken(
		t,
		f,
		"/allowlist",
		newPolicy,
		token,
	)
	requireStatus(
		t,
		request(
			replicas[0],
			http.MethodPut,
			"/allowlist",
			newPolicy,
			token,
			"",
		),
		http.StatusNoContent,
	)
	response = request(
		replicas[2],
		http.MethodPut,
		"/allowlist",
		newPolicy,
		token,
		"",
	)
	requireStatus(
		t,
		response,
		http.StatusConflict,
	)
	if strings.TrimSpace(response.Body.String()) != operatorauth.ErrTokenReused.Error() {
		t.Fatal("recovered token was not spent exactly once")
	}
}
