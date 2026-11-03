// pod-netcheck is the connected acceptance workload of the pod role: an
// application that probes the pod's network and reports over HTTP, the
// in-pod checker that reads that report, the CDS guest probe and an
// independently ready application. The argv of each mode is defined by the
// podfixture package, which the pod documents and allowlist rules pin.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

const listen = "0.0.0.0:8080"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: pod-netcheck serve|check CONFIG | cds-probe HOST [HOLD] | hello")
		return 2
	}
	switch args[0] {
	case podfixture.ModeServe:
		if len(args) != 2 {
			return 2
		}
		a, err := newApp(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		go a.probeLoop()
		return serve(a)
	case podfixture.ModeCheck:
		if len(args) != 2 {
			return 2
		}
		cfg, err := parseConfig(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return newChecker(cfg).run(os.Stdout)
	case podfixture.ModeCDSProbe:
		p, code := newProbe(args[1:])
		if code != 0 {
			return code
		}
		if code := p.prepare(); code != 0 {
			return code
		}
		if !p.restarted() {
			go func() {
				if code, exit := p.observe(); exit {
					os.Exit(code)
				}
			}()
		}
		return serve(p)
	case podfixture.ModeHello:
		return serve(http.HandlerFunc(hello))
	}
	return 2
}

// serve runs the handler on the pod's application port until it fails.
func serve(h http.Handler) int {
	server := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintln(os.Stderr, server.ListenAndServe())
	return 1
}

// hello answers only the probes; nothing else is expected of it.
func hello(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/live" || r.URL.Path == "/ready" {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}
