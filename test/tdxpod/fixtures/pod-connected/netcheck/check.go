package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

// checker is the check mode: it reads the application's report on the pod's
// loopback and exits with the verdict authenticated pod status carries. It
// requires the readiness cycle in order, then Soak of healthy time.
type checker struct {
	cfg       config
	now       func() float64 // seconds since start, monotonic; its own clock, not the application's
	sleep     func(time.Duration)
	transport http.RoundTripper
	reportURL string
}

func newChecker(cfg config) *checker {
	start := time.Now()
	return &checker{cfg: cfg, now: func() float64 { return time.Since(start).Seconds() }, sleep: time.Sleep,
		transport: http.DefaultTransport, reportURL: "http://127.0.0.1:8080/report"}
}

// reportState is what the checker reads of the application's report.
type reportState struct {
	PodUID    string                 `json:"podUID"`
	Instance  string                 `json:"instance"`
	FirstPass *float64               `json:"firstPass"`
	CheckedAt *float64               `json:"checkedAt"`
	Elapsed   float64                `json:"elapsed"`
	Ready     bool                   `json:"ready"`
	Checks    map[string]checkResult `json:"checks"`
}

func (c *checker) read() (*reportState, bool) {
	resp, err := (&http.Client{Transport: c.transport, Timeout: 3 * time.Second}).Get(c.reportURL)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var state reportState
	if json.Unmarshal(body, &state) != nil || state.PodUID != c.cfg.PodUID {
		return nil, false
	}
	return &state, true
}

func (c *checker) run(out io.Writer) int {
	var initialReady, forcedFalse, recovered bool
	for c.now() < podfixture.CheckerDeadline.Seconds() {
		if state, ok := c.read(); ok {
			if state.FirstPass == nil {
				if c.now() > podfixture.InitialDeadline.Seconds() {
					fmt.Fprintln(out, "initial network acceptance timed out")
					return podfixture.ExitInitialTimeout
				}
			} else {
				age := state.Elapsed - *state.FirstPass
				fresh := state.CheckedAt != nil && state.Elapsed-*state.CheckedAt >= 0 && state.Elapsed-*state.CheckedAt <= podfixture.Freshness.Seconds()
				healthy := len(state.Checks) == len(checkNames) && allOK(state.Checks) && fresh
				if healthy && age >= podfixture.ReadyAfter.Seconds() && age < podfixture.DipStart.Seconds() && state.Ready {
					initialReady = true
				}
				if healthy && age >= podfixture.DipStart.Seconds() && age < podfixture.DipEnd.Seconds() && !state.Ready {
					forcedFalse = true
				}
				if healthy && age >= podfixture.DipEnd.Seconds() && state.Ready {
					recovered = true
				}
				cycle := initialReady && forcedFalse && recovered
				if age >= podfixture.TransitionDeadline.Seconds() && !cycle {
					fmt.Fprintln(out, "readiness transition acceptance failed")
					return podfixture.ExitTransitions
				}
				if age >= podfixture.Soak.Seconds() && healthy && cycle {
					verdict, _ := json.Marshal(map[string]any{"result": "pass", "elapsedAfterInitialPass": age, "instance": state.Instance, "checks": state.Checks})
					fmt.Fprintln(out, string(verdict))
					return 0
				}
			}
		}
		c.sleep(podfixture.CheckerPeriod)
	}
	fmt.Fprintln(out, "post-soak network acceptance timed out")
	return podfixture.ExitSoakTimeout
}
