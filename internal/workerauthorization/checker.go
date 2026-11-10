package workerauthorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const maxPolicyBytes = 4 << 20

type Checker struct {
	client          *http.Client
	measurementsURL string
	evidence        *armtls.SelfSignedProvider
	verificationURL string
}

// The client authenticates CDS; evidence and verification belong to this worker.
func New(
	client *http.Client,
	cdsURL string,
	evidence *armtls.SelfSignedProvider,
	verificationURL string,
) *Checker {
	return &Checker{
		client:          client,
		measurementsURL: strings.TrimRight(cdsURL, "/") + "/measurements",
		evidence:        evidence,
		verificationURL: verificationURL,
	}
}

// An error leaves eligibility unknown; false with nil error establishes a mismatch.
func (c *Checker) Check(ctx context.Context) (bool, error) {
	values, err := c.fetchPolicy(ctx)
	if err != nil {
		return false, err
	}
	if len(values.Images) == 0 {
		return false, nil
	}
	certificate, _, err := c.evidence.Provision(ctx)
	if err != nil {
		return false, fmt.Errorf("acquire worker evidence: %w", err)
	}
	if certificate == nil || certificate.Leaf == nil {
		return false, fmt.Errorf("worker evidence lacks a certificate leaf")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	policy := armtls.Pins(values.Policy()).VerifyPolicy(c.verificationURL)
	policy.AttestationVerifyTimeout = 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		policy.AttestationVerifyTimeout = min(policy.AttestationVerifyTimeout, time.Until(deadline))
	}
	_, err = armtls.VerifyCert(certificate.Leaf, policy, nil)
	if canceled := ctx.Err(); canceled != nil {
		return false, canceled
	}
	if errors.Is(err, armtls.ErrPolicyViolation) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *Checker) fetchPolicy(ctx context.Context) (refvalues.ReferenceValues, error) {
	var values refvalues.ReferenceValues
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.measurementsURL, nil)
	if err != nil {
		return values, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return values, fmt.Errorf("fetch worker policy: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return values, fmt.Errorf("fetch worker policy: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPolicyBytes+1))
	if err != nil {
		return values, err
	}
	if len(body) > maxPolicyBytes {
		return values, fmt.Errorf("worker policy exceeds %d bytes", maxPolicyBytes)
	}
	if err := strictjson.Validate(body); err != nil {
		return values, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return values, err
	}
	var measurements []json.RawMessage
	if err := json.Unmarshal(document["measurements"], &measurements); err != nil || measurements == nil {
		return values, fmt.Errorf("worker policy requires a measurements array")
	}
	return refvalues.ParseRendered(body)
}
