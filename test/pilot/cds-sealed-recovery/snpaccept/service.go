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
	Operation   string     `json:"operation"`
	Nonce       []byte     `json:"nonce"`
	Measurement string     `json:"measurement"`
	Parameters  Parameters `json:"parameters"`
	Collateral  Collateral `json:"collateral,omitempty"`
	OperatorKey []byte     `json:"operator_key,omitempty"`
}
type Result struct {
	Operation  string         `json:"operation"`
	Passed     bool           `json:"passed"`
	Launch     []byte         `json:"launch,omitempty"`
	Parameters Parameters     `json:"parameters"`
	Checks     map[string]any `json:"checks,omitempty"`
	Error      string         `json:"error,omitempty"`
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
	relay := NewRelay(ctx)
	var started atomic.Bool
	var result atomic.Pointer[Reply]
	gate := make(chan struct{}, 40)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/start", func(w http.ResponseWriter, r *http.Request) {
		var q Request
		if decodeHTTP(w, r, &q, 4<<20) != nil || len(q.Nonce) != 32 || bytes.Equal(q.Nonce, make([]byte, 32)) || h.CheckMeasurement(q.Measurement) != nil || (q.Operation != "enroll" && q.Operation != "seed" && q.Operation != "recover") {
			http.Error(w, "invalid bounded phase request", 400)
			return
		}
		if !started.CompareAndSwap(false, true) {
			http.Error(w, "phase already started", 409)
			return
		}
		go func() {
			var out Result
			if q.Operation == "enroll" {
				launch, p, err := h.Enroll(ctx)
				out = Result{Operation: q.Operation, Passed: err == nil, Launch: launch, Parameters: p}
				if err != nil {
					out.Error = err.Error()
				}
			} else {
				out = run(q, relay)
			}
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
