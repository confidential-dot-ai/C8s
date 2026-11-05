package cdsha

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// OperatorCommand is the exact signed PUT request admitted by a CDS. One log
// entry spends its token and applies its mutation, in that order. A valid token
// is spent even when parsing, a precondition, or the store refuses the write.
// AtMS is the origin's admission time; replay never consults a wall clock.
// EscapedPath is present only when URL.EscapedPath differs from URL.Path.
type OperatorCommand struct {
	Token       string `json:"token"`
	Path        string `json:"path"`
	EscapedPath string `json:"escaped_path,omitempty"`
	IfMatch     string `json:"if_match,omitempty"`
	Body        []byte `json:"body"`
	AtMS        int64  `json:"at_ms"`
}

// OperatorResult contains only the public response, never an existing secret
// value. Transport failure is distinct: a lost receipt is an unknown outcome,
// and a new request with that spent token is still refused.
type OperatorResult struct {
	Code    int    `json:"code"`
	Body    []byte `json:"body,omitempty"`
	JSON    bool   `json:"json,omitempty"`
	NoStore bool   `json:"no_store,omitempty"`
}

func operatorText(code int, message string) Result {
	return Result{Operator: &OperatorResult{Code: code, Body: []byte(message)}}
}

func operatorJSON(code int, value any) Result {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err) // Only fixed response structs reach this helper.
	}
	return Result{Operator: &OperatorResult{Code: code, Body: append(body, '\n'), JSON: true, NoStore: true}}
}

func (f *FSM) applyOperator(c OperatorCommand) Result {
	if c.AtMS <= 0 || (c.Path != "/allowlist" && c.Path != routes.Path && !strings.HasPrefix(c.Path, "/secrets/")) {
		return Result{Stop: f.stop(errors.New("invalid operator command"))}
	}
	rawPath := c.Path
	if c.EscapedPath != "" {
		decoded, err := url.PathUnescape(c.EscapedPath)
		if err != nil || decoded != c.Path {
			return Result{Stop: f.stop(errors.New("operator path differs from its signed path"))}
		}
		rawPath = c.EscapedPath
	}
	// The ingress checked time validity before admitting the request. Every
	// replay independently verifies the pinned key and exact method/path/body
	// binding, including long after the original token has expired.
	if err := operatorauth.VerifyStored(f.launch.OperatorKeys, c.Token, http.MethodPut, c.Path, c.Body); err != nil {
		return Result{Stop: f.stop(fmt.Errorf("invalid committed operator authorization: %w", err))}
	}
	version, matchable := allowlist.OperatorVersion(c.IfMatch)
	if c.Path == "/allowlist" && !matchable {
		// Preserve the existing exception: an impossible If-Match is rejected
		// before authentication and does not spend a token.
		return operatorText(http.StatusPreconditionFailed, allowlist.InvalidOperatorVersion)
	}
	spent := f.allowlist.Apply(allowlist.Command{Op: allowlist.OpConsumeToken, Token: c.Token, AtMS: c.AtMS})
	if spent.LocalStoreFault() {
		return Result{Stop: f.stopLocal(fmt.Errorf("operator token store: %s", spent.Message))}
	}
	if err := spent.Refusal(); err != nil {
		if errors.Is(err, operatorauth.ErrTokenReused) {
			return operatorText(http.StatusConflict, operatorauth.ErrTokenReused.Error())
		}
		return operatorText(http.StatusServiceUnavailable, operatorauth.ErrTokenNotRecorded.Error())
	}
	switch c.Path {
	case "/allowlist":
		cmd, err := allowlist.PrepareOperatorReplace(c.Body, version, c.Token)
		if err != nil {
			return operatorText(http.StatusUnprocessableEntity, err.Error())
		}
		cmd.AtMS = c.AtMS
		res := f.allowlist.Apply(cmd)
		if errors.Is(res.Refusal(), allowlist.ErrVersionMismatch) {
			return operatorText(http.StatusPreconditionFailed, res.Refusal().Error()+"; fetch it and apply the change again")
		}
		return f.operatorAllowlistResult(res)
	case routes.Path:
		ca := f.CA()
		if ca == nil {
			return operatorText(http.StatusServiceUnavailable, "internal server error")
		}
		manifest, err := routes.Parse(c.Body)
		if err == nil {
			err = manifest.CheckAnchorsExclude([]*x509.Certificate{ca.Cert})
		}
		if err != nil {
			return operatorText(http.StatusUnprocessableEntity, err.Error())
		}
		res := f.allowlist.Apply(allowlist.Command{Op: allowlist.OpReplaceRoutes, AtMS: c.AtMS,
			Routes: &routes.Envelope{Manifest: c.Body, Token: c.Token}, RouteDigest: c.IfMatch})
		switch err := res.Refusal(); {
		case errors.Is(err, allowlist.ErrRevisionNotGreater):
			return operatorText(http.StatusConflict, err.Error())
		case errors.Is(err, allowlist.ErrDigestMismatch):
			return operatorText(http.StatusPreconditionFailed, err.Error()+"; fetch the stored manifest and apply the change again")
		}
		return f.operatorAllowlistResult(res)
	default:
		cmd, status, err := secrets.PrepareOperatorWrite(rawPath, c.Body)
		if err != nil {
			return operatorText(status, err.Error())
		}
		defer clear(cmd.Value)
		res := f.secrets.Apply(cmd)
		defer clear(res.Current)
		if err := res.Refusal(); err != nil {
			if errors.Is(err, secrets.ErrStoreFull) {
				return operatorJSON(http.StatusInsufficientStorage, types.ErrorResponse{
					Error: types.ErrorCodeSecretStoreFull, Message: "secret storage limit reached"})
			}
			return operatorText(http.StatusInternalServerError, "secret write failed")
		}
		response := secrets.PutResponse{Path: cmd.Path, Existing: res.HeldOrigin}
		status = http.StatusOK
		if !res.HeldExists {
			status, response.Created = http.StatusCreated, true
		} else if cmd.Op == secrets.OpPutIfAbsent {
			status = http.StatusConflict
		}
		return operatorJSON(status, response)
	}
}

func (f *FSM) operatorAllowlistResult(res allowlist.Result) Result {
	if res.LocalStoreFault() {
		return Result{Stop: f.stopLocal(fmt.Errorf("operator mutation store: %s", res.Message))}
	}
	if res.Refusal() != nil {
		return operatorText(http.StatusInternalServerError, "internal server error")
	}
	return Result{Operator: &OperatorResult{Code: http.StatusNoContent}}
}
