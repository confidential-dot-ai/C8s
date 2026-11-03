// cds-load compares the same attested HTTP workload against either CDS backend.
// It is an operator-run pilot tool: secret-create writes synthetic values to an
// isolated cluster; allowlist-read changes no state. It never retries a write.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type endpoint struct {
	url    string
	client *http.Client
}
type sample struct {
	elapsed time.Duration
	status  int
}
type report struct {
	Mode              string      `json:"mode"`
	Run               string      `json:"run"`
	Requests          int         `json:"requests"`
	Concurrency       int         `json:"concurrency"`
	Seconds           float64     `json:"seconds"`
	RequestsPerSecond float64     `json:"requests_per_second"`
	Successes         int         `json:"successes"`
	Statuses          map[int]int `json:"statuses"`
	SuccessP50MS      float64     `json:"success_p50_ms"`
	SuccessP95MS      float64     `json:"success_p95_ms"`
	SuccessP99MS      float64     `json:"success_p99_ms"`
	AllP99MS          float64     `json:"all_p99_ms"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	targets := flag.String("targets", "", "comma-separated direct HTTPS CDS origins")
	pins := flag.String("cds-pin", "", "CDS image and launch-file pin document")
	mode := flag.String("mode", "allowlist-read", "allowlist-read or secret-create (writes synthetic secrets)")
	keyFile := flag.String("operator-key", "", "operator PEM file, required for secret-create")
	count := flag.Int("n", 1000, "number of requests; no automatic retries")
	concurrency := flag.Int("concurrency", 1, "maximum concurrent requests")
	timeout := flag.Duration("timeout", 15*time.Second, "per-request deadline")
	flag.Parse()
	if *targets == "" || *pins == "" || *count < 1 || *count > 1_000_000 || *concurrency < 1 || *concurrency > 1024 || *timeout <= 0 {
		return errors.New("provide --targets, --cds-pin, 1..1000000 requests, 1..1024 concurrency and a positive timeout")
	}
	if *mode != "allowlist-read" && *mode != "secret-create" {
		return errors.New("unknown workload")
	}
	var signer *operatorauth.Signer
	if *mode == "secret-create" {
		key, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		signer, err = operatorauth.NewSignerFromKeyPEM(key)
		clear(key)
		if err != nil {
			return err
		}
	}
	var endpoints []endpoint
	for _, named := range strings.Split(*targets, ",") {
		origin := strings.TrimRight(strings.TrimSpace(named), "/")
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("targets must be HTTPS origins")
		}
		o := cdsconn.Options{URL: origin, MeasurementsConfig: *pins, DirectCDS: true, Timeout: *timeout}
		client, err := o.HTTPClient(context.Background())
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		// Warm the attested connection before measuring the steady workload.
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin+"/readyz", nil)
		if err != nil {
			return err
		}
		res, err := client.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("target not ready: HTTP %d", res.StatusCode)
		}
		endpoints = append(endpoints, endpoint{origin, client})
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	runID := hex.EncodeToString(id[:])
	results := make([]sample, *count)
	jobs := make(chan int)
	var wg sync.WaitGroup
	start := time.Now()
	for range min(*concurrency, *count) {
		wg.Go(func() {
			for i := range jobs {
				target := endpoints[i%len(endpoints)]
				method, path := http.MethodGet, "/allowlist"
				var body []byte
				if signer != nil {
					method = http.MethodPut
					path = fmt.Sprintf("/secrets/pilot/%s/%d", runID, i)
					body = []byte(`{"value":"c3ludGhldGljLXBpbG90LXZhbHVl"}`)
				}
				began := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				req, err := http.NewRequestWithContext(ctx, method, target.url+path, bytes.NewReader(body))
				if err == nil && signer != nil {
					var auth string
					auth, err = signer.Authorization(method, path, body)
					req.Header.Set("Authorization", auth)
					req.Header.Set("Content-Type", "application/json")
				}
				status := 0
				if err == nil {
					var res *http.Response
					res, err = target.client.Do(req)
					if err == nil {
						_, err = io.Copy(io.Discard, io.LimitReader(res.Body, 16<<20))
						res.Body.Close()
						if err == nil {
							status = res.StatusCode
						}
					}
				}
				cancel()
				results[i] = sample{time.Since(began), status}
			}
		})
	}
	for i := range *count {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	duration := time.Since(start)
	r := report{Mode: *mode, Run: runID, Requests: *count, Concurrency: *concurrency, Seconds: duration.Seconds(), RequestsPerSecond: float64(*count) / duration.Seconds(), Statuses: map[int]int{}}
	var success, all []time.Duration
	expected := http.StatusOK
	if signer != nil {
		expected = http.StatusCreated
	}
	for _, result := range results {
		r.Statuses[result.status]++
		all = append(all, result.elapsed)
		if result.status == expected {
			success = append(success, result.elapsed)
		}
	}
	slices.Sort(success)
	slices.Sort(all)
	r.Successes = len(success)
	r.SuccessP50MS = percentile(success, .5)
	r.SuccessP95MS = percentile(success, .95)
	r.SuccessP99MS = percentile(success, .99)
	r.AllP99MS = percentile(all, .99)
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		return err
	}
	if r.Successes != r.Requests {
		return errors.New("some requests failed; status 0 means a transport failure or timeout; write outcomes may be unknown")
	}
	return nil
}

func percentile(values []time.Duration, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	return float64(values[int(math.Ceil(float64(len(values))*p))-1]) / float64(time.Millisecond)
}
