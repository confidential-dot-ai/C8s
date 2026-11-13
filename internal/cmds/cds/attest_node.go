package cds

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"net/http"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/httputil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// nodeIssuance is the node profile: a node CVM, which may present an
// inventory-signed token for the sandbox it serves. Every request without pod
// claims is one.
type nodeIssuance struct {
	h          AttestHandler
	req        types.AttestRequestBody
	remoteAddr string
}

// bind verifies the sandbox token (docs/armtls.md, "Sandbox identity") before
// the expensive evidence round-trip; its sandbox ID reaches the leaf only
// after every later gate passes. Without a token the sandbox is empty.
func (n nodeIssuance) bind(ctx context.Context, w http.ResponseWriter, csrPub *ecdsa.PublicKey, challenge []byte) ([64]byte, workloadclaims.VerifiedSandbox, bool) {
	var sandbox workloadclaims.VerifiedSandbox
	if len(n.req.SandboxToken) > 0 {
		verified, err := n.h.verifySandboxToken(ctx, n.req.SandboxToken, csrPub, challenge)
		if err != nil {
			// The caller names the host CDS dials, so the detail stays in the log.
			slog.Warn("sandbox token rejected", "error", err, "remote_addr", n.remoteAddr)
			httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeCSRDenied, "sandbox token rejected")
			return [64]byte{}, sandbox, false
		}
		sandbox = verified
	}
	reportData, err := armtls.ReportDataForKey(csrPub, challenge)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, types.ErrorCodeInvalidCSR, err.Error())
		return [64]byte{}, sandbox, false
	}
	return reportData, sandbox, true
}

func (n nodeIssuance) admitImage(w http.ResponseWriter, verified remote.VerifyResponse, launchDigest string) bool {
	if err := n.h.matchPinnedNodeImage(verified, n.req.Evidence.Platform, n.req.RuntimeExtensions); err != nil {
		slog.Warn("node identity does not match policy", "launch_digest", launchDigest, "error", err, "remote_addr", n.remoteAddr)
		httputil.WriteError(w, http.StatusForbidden, types.ErrorCodeMeasurementDenied, "node identity not allowed")
		return false
	}
	return true
}

func (n nodeIssuance) resolveWorkload(ctx context.Context, sandbox workloadclaims.VerifiedSandbox) (*armtls.MatchedWorkload, bool, error) {
	return n.h.resolveSandboxWorkload(ctx, sandbox)
}

func (n nodeIssuance) clientDocument() ([]byte, string) {
	return nil, ""
}

func (n nodeIssuance) recordIssued(sandbox workloadclaims.VerifiedSandbox) {
	n.h.recordSandboxBinding(sandbox)
}
