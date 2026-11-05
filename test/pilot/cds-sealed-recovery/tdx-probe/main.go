//go:build linux

// tdx-probe qualifies native attestation and reads the module's sealing feature
// bit. It never requests, accepts, stores, or releases a secret key.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/verify/trust"
)

const featuresPath = "/sys/devices/virtual/misc/tdx_guest/cds_pilot_features"
const launchPath = "/run/confai/operator-pubkey"
const fieldID = "0a00000300000008"

type request struct {
	Nonce []byte `json:"nonce"`
}

type result struct {
	Version      int    `json:"version"`
	FieldID      string `json:"field_id"`
	Status       string `json:"status"`
	Features     string `json:"features"`
	LaunchSHA256 string `json:"launch_sha256"`
}

type reply struct {
	Result result `json:"result"`
	Quote  []byte `json:"quote"`
}

func binding(q request, r result) [64]byte {
	b, _ := json.Marshal(struct {
		Request request `json:"request"`
		Result  result  `json:"result"`
	}{q, r})
	return sha512.Sum512(append([]byte("c8s/cds-tdx-capability-probe/v1\x00"), b...))
}

func decode(b []byte, v any) error {
	if err := strictjson.Validate(b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func bounded(path string, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, size+1))
	if err == nil && (len(b) == 0 || int64(len(b)) > size) {
		err = errors.New("empty or oversized input")
	}
	return b, err
}

func parseFeatures(b []byte) (status, features string, err error) {
	parts := strings.Fields(string(b))
	if len(parts) != 2 {
		return "", "", errors.New("malformed native capability result")
	}
	for _, s := range parts {
		if len(s) != 16 {
			return "", "", errors.New("malformed native capability value")
		}
		if _, e := hex.DecodeString(s); e != nil {
			return "", "", e
		}
	}
	return parts[0], parts[1], nil
}

func collect(q request) (reply, error) {
	if len(q.Nonce) != 32 {
		return reply{}, errors.New("32-byte fresh nonce required")
	}
	b, err := bounded(featuresPath, 64)
	if err != nil {
		return reply{}, err
	}
	status, features, err := parseFeatures(b)
	if err != nil {
		return reply{}, err
	}
	launch, err := bounded(launchPath, 64<<10)
	if err != nil {
		return reply{}, err
	}
	h := sha256.Sum256(launch)
	r := result{Version: 1, FieldID: fieldID, Status: status, Features: features, LaunchSHA256: hex.EncodeToString(h[:])}
	p, err := client.GetQuoteProvider()
	if err != nil {
		return reply{}, err
	}
	if err := p.IsSupported(); err != nil {
		return reply{}, err
	}
	quote, err := p.GetRawQuote(binding(q, r))
	return reply{Result: r, Quote: quote}, err
}

// One bounded actor owns native quote collection. Concurrent callers receive
// backpressure; no goroutines or requests accumulate behind the hardware call.
func serve() error {
	type job struct {
		q        request
		response chan reply
		err      chan error
	}
	jobs := make(chan job)
	go func() {
		for j := range jobs {
			r, err := collect(j.q)
			if err != nil {
				j.err <- err
			} else {
				j.response <- r
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("POST /v1/probe", func(w http.ResponseWriter, r *http.Request) {
		var q request
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256))
		if err != nil || decode(b, &q) != nil || len(q.Nonce) != 32 {
			http.Error(w, "invalid bounded probe request", 400)
			return
		}
		j := job{q, make(chan reply, 1), make(chan error, 1)}
		select {
		case jobs <- j:
		default:
			http.Error(w, "probe busy", 429)
			return
		}
		select {
		case out := <-j.response:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case err := <-j.err:
			http.Error(w, err.Error(), 503)
		case <-r.Context().Done():
		}
	})
	s := &http.Server{Addr: ":6443", Handler: mux, ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	return s.ListenAndServe()
}

type recordedCollateral struct {
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}
type getter struct{ data map[string]recordedCollateral }

func (g *getter) Get(url string) (map[string][]string, []byte, error) {
	if r, ok := g.data[url]; ok {
		return r.Headers, r.Body, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h, b, err := (&trust.SimpleHTTPSGetter{}).GetContext(ctx, url)
	if err == nil {
		g.data[url] = recordedCollateral{h, b}
	}
	return h, b, err
}

func verify(q request, r reply, launch []byte, manifest string) (map[string]any, map[string]recordedCollateral, error) {
	if len(q.Nonce) != 32 || r.Result.Version != 1 || r.Result.FieldID != fieldID || len(launch) == 0 || len(r.Quote) > 64<<10 {
		return nil, nil, errors.New("independent nonce, image and launch required")
	}
	if _, _, err := parseFeatures([]byte(r.Result.Status + " " + r.Result.Features)); err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(launch)
	if r.Result.LaunchSHA256 != hex.EncodeToString(h[:]) {
		return nil, nil, errors.New("launch hash mismatch")
	}
	data := binding(q, r.Result)
	g := &getter{make(map[string]recordedCollateral)}
	v, err := tdx.VerifyQuoteBytes(r.Quote, teetypes.VerifyParams{ExpectedReportData: data[:]}, teetypes.PlatformTDX,
		tdx.Options{CheckRevocations: true, GetCollateral: true, Getter: g})
	if err != nil {
		return nil, g.data, err
	}
	pins, err := runtimemeasure.LoadImageManifestFor(manifest, teetypes.FamilyTDX)
	if err == nil {
		err = pins.Verify(v)
	}
	if err == nil {
		err = runtimemeasure.VerifyBinding(v, launch, nil)
	}
	if err != nil {
		return nil, g.data, err
	}
	features, _ := strconv.ParseUint(r.Result.Features, 16, 64)
	queryOK := r.Result.Status == "0000000000000000"
	return map[string]any{"attestation_chain_verified": true, "collateral_verified": true, "revocations_checked": true,
		"image_pins_verified": true, "launch_binding_verified": true, "result": r.Result,
		"feature_query_succeeded": queryOK, "native_sealing_advertised": queryOK && features&(1<<12) != 0,
		"native_sealing_qualified": false, "full_acceptance_passed": false, "production_ready": false,
		"verification": v}, g.data, nil
}

func writeNew(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

func run() error {
	mode := flag.String("mode", "", "serve or verify")
	qpath := flag.String("request", "", "original request")
	rpath := flag.String("reply", "", "untrusted reply")
	lpath := flag.String("launch", "", "independent launch bytes")
	manifest := flag.String("manifest", "", "independently built image manifest")
	out := flag.String("receipt", "", "new verified receipt")
	col := flag.String("collateral", "", "new public collateral file")
	flag.Parse()
	if *mode == "serve" {
		return serve()
	}
	if *mode != "verify" {
		return errors.New("explicit serve or verify mode required")
	}
	var q request
	var r reply
	for _, item := range []struct {
		path  string
		value any
	}{{*qpath, &q}, {*rpath, &r}} {
		b, err := bounded(item.path, 128<<10)
		if err != nil {
			return err
		}
		if err = decode(b, item.value); err != nil {
			return err
		}
	}
	launch, err := bounded(*lpath, 64<<10)
	if err != nil {
		return err
	}
	receipt, collateral, err := verify(q, r, launch, *manifest)
	if err != nil {
		return err
	}
	if err = writeNew(*col, collateral); err != nil {
		return err
	}
	return writeNew(*out, receipt)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
