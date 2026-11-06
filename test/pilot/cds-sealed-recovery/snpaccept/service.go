//go:build linux

package snpaccept

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"golang.org/x/net/netutil"
)

type Request struct {
	Operation       string              `json:"operation"`
	Nonce           []byte              `json:"nonce"`
	Measurement     string              `json:"measurement"`
	Parameters      Parameters          `json:"parameters"`
	Collateral      Collateral          `json:"collateral,omitempty"`
	IntelCollateral IntelCollateral     `json:"intel_collateral,omitempty"`
	OperatorKey     []byte              `json:"operator_key,omitempty"`
	Custody         *CustodyRequest     `json:"custody,omitempty"`
	Custodies       []TDXCustodyRequest `json:"custodies,omitempty"`
	Copy            *CustodyCopy        `json:"copy,omitempty"`
}
type Result struct {
	Operation     string              `json:"operation"`
	Passed        bool                `json:"passed"`
	Launch        []byte              `json:"launch,omitempty"`
	Parameters    Parameters          `json:"parameters"`
	Checks        map[string]any      `json:"checks,omitempty"`
	Error         string              `json:"error,omitempty"`
	Derivation    *DerivationIdentity `json:"derivation,omitempty"`
	Custody       *CustodyGrant       `json:"custody,omitempty"`
	CustodyGrants []*CustodyGrant     `json:"custody_grants,omitempty"`
	Copy          *CustodyCopy        `json:"copy,omitempty"`
}
type Reply struct {
	Result Result `json:"result"`
	Report []byte `json:"report"`
}

func Binding(q Request, result Result) [64]byte {
	b, _ := json.Marshal(struct {
		Domain  string  `json:"domain"`
		Request Request `json:"request"`
		Result  Result  `json:"result"`
	}{"c8s/cds-snp-integrated-acceptance/v1", q, result})
	return sha512.Sum512(b)
}
func decodeHTTP(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	if err := strictjson.Validate(b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// Serve accepts exactly one enrollment or test phase per VM. The bounded
// storage relay stays available while that phase runs. No remote path accepts
// executable code, file paths, process arguments, or plaintext custody keys.
func Serve(ctx context.Context, h *Hardware, run func(Request, *Relay) Result) error {
	return servePhases(ctx, h, false, validSNPPhase, func(q Request, relay *Relay) Result {
		var out Result
		p := q.Parameters
		if q.Operation == "enroll" {
			p = Parameters{h.ReportInfo.GuestSvn, h.ReportInfo.CommittedTcb}
		}
		var identity *DerivationIdentity
		var identityErr error
		delegating := q.Operation == "delegate" || q.Operation == "delegate-three"
		if delegating && q.Copy != nil {
			identity, identityErr = h.CopyIdentity(ctx, *q.Copy)
		} else if q.Operation == "enroll" || delegating {
			identity, identityErr = h.PublicIdentity(ctx, p)
		}
		if q.Operation == "enroll" {
			launch, p, err := h.Enroll(ctx)
			out = Result{Operation: q.Operation, Passed: err == nil, Launch: launch, Parameters: p}
			if err != nil {
				out.Error = err.Error()
			}
		} else if q.Operation == "delegate-three" {
			grants, err := delegateThree(q.Custodies, func(r TDXCustodyRequest) (*CustodyGrant, error) {
				return h.DelegateTDX(ctx, p, q.Copy, &r.Recipient, r.Collateral)
			})
			out = Result{Operation: q.Operation, Passed: err == nil, CustodyGrants: grants, Parameters: p}
			if err != nil {
				out.Error = err.Error()
			}
		} else if q.Operation == "delegate" {
			var grant *CustodyGrant
			var err error
			if q.Custody != nil && q.Custody.Family == "tdx" {
				grant, err = h.DelegateTDX(ctx, p, q.Copy, q.Custody, q.IntelCollateral)
			} else if q.Copy != nil {
				grant, err = h.DelegateCopy(ctx, *q.Copy, q.Custody, q.Collateral)
			} else {
				grant, err = h.Delegate(ctx, p, q.Custody, q.Collateral)
			}
			out = Result{Operation: q.Operation, Passed: err == nil, Custody: grant, Parameters: p}
			if err != nil {
				out.Error = err.Error()
			}
		} else if q.Operation == "copy" {
			copy, identityValue, err := h.EnrollCopy(ctx, relay)
			identity = identityValue
			out = Result{Operation: q.Operation, Passed: err == nil, Copy: copy}
			if err != nil {
				out.Error = err.Error()
			} else {
				out.Parameters = copy.Parameters
			}
		} else {
			out = run(q, relay)
		}
		out.Derivation = identity
		if identityErr != nil {
			out.Passed = false
			out.Error = "public derivation identity unavailable: " + identityErr.Error()
		}
		return out
	})
}

// ServeTDX exposes only CDS acceptance phases. Enrollment and durable custody
// remain exclusively in the SNP custodian, with no key upload or software root.
func ServeTDX(ctx context.Context, h *TDXHardware, run func(Request, *Relay) Result) error {
	return servePhases(ctx, h, true, func(q Request) bool {
		return (q.Operation == "seed" || q.Operation == "recover") && q.Copy == nil && q.Custody == nil && len(q.Custodies) == 0
	}, run)
}

type phaseReporter interface {
	Report(context.Context, [64]byte) ([]byte, error)
	CheckMeasurement(string) error
}

func servePhases(ctx context.Context, h phaseReporter, inspect bool, valid func(Request) bool, run func(Request, *Relay) Result) error {
	relay := NewRelay(ctx)
	var started atomic.Bool
	var result atomic.Pointer[Reply]
	gate := make(chan struct{}, 40)
	mux := http.NewServeMux()
	if inspect {
		// Obtain fresh public Intel collateral before the single CDS phase.
		// This endpoint can only quote a bounded nonce and the fixed launch;
		// it cannot enroll, derive, upload, or release any key material.
		mux.HandleFunc("POST /v1/inspect", func(w http.ResponseWriter, r *http.Request) {
			var q Request
			if decodeHTTP(w, r, &q, 4096) != nil || q.Operation != "inspect" || len(q.Nonce) != 32 || bytes.Equal(q.Nonce, make([]byte, 32)) || h.CheckMeasurement(q.Measurement) != nil || len(q.OperatorKey) != 0 || len(q.Collateral) != 0 || len(q.IntelCollateral) != 0 || q.Copy != nil || q.Custody != nil || len(q.Custodies) != 0 || q.Parameters != (Parameters{}) {
				http.Error(w, "bounded public inspection required", 400)
				return
			}
			out := Result{Operation: "inspect", Passed: true}
			report, err := h.Report(r.Context(), Binding(q, out))
			if err != nil {
				http.Error(w, "hardware quote unavailable", 503)
				return
			}
			_ = json.NewEncoder(w).Encode(Reply{Result: out, Report: report})
		})
	}
	mux.HandleFunc("POST /v1/start", func(w http.ResponseWriter, r *http.Request) {
		var q Request
		if decodeHTTP(w, r, &q, 4<<20) != nil || len(q.Nonce) != 32 || bytes.Equal(q.Nonce, make([]byte, 32)) || h.CheckMeasurement(q.Measurement) != nil || !valid(q) {
			http.Error(w, "invalid bounded phase request", 400)
			return
		}
		if !started.CompareAndSwap(false, true) {
			http.Error(w, "phase already started", 409)
			return
		}
		go func() {
			out := run(q, relay)
			raw, err := h.Report(ctx, Binding(q, out))
			if err != nil {
				out.Passed = false
				out.Error = "final hardware report unavailable"
			}
			result.Store(&Reply{out, raw})
			clear(q.OperatorKey)
		}()
		w.WriteHeader(202)
	})
	mux.HandleFunc("GET /v1/result", func(w http.ResponseWriter, r *http.Request) {
		p := result.Load()
		if p == nil {
			w.WriteHeader(202)
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	})
	mux.HandleFunc("GET /v1/storage", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		q, err := relay.Poll(ctx)
		if err != nil {
			w.WriteHeader(204)
			return
		}
		_ = json.NewEncoder(w).Encode(q)
	})
	mux.HandleFunc("POST /v1/storage", func(w http.ResponseWriter, r *http.Request) {
		var response StorageResponse
		if decodeHTTP(w, r, &response, 32<<20) != nil || response.Status < 200 || response.Status > 599 {
			http.Error(w, "invalid storage response", 400)
			return
		}
		if !relay.Complete(r.Context(), response) {
			w.WriteHeader(409)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			http.Error(w, "connection backpressure", 429)
			return
		}
		mux.ServeHTTP(w, r)
	})
	l, err := net.Listen("tcp", ":6443")
	if err != nil {
		return err
	}
	s := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() { <-ctx.Done(); _ = s.Close() }()
	err = s.Serve(netutil.LimitListener(l, 48))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
