// What a replica reports about its cluster, and what it refuses while it may
// not serve that cluster.
//
// The reports are public, as /ca and /measurements are: none of them carries a
// key, a secret value or a token, and a node that no longer recognises a
// replica's image reads the pin decree before it can trust any replica. The
// one write is the operator's decree, whose signature over everything it says
// is its authority.

package cds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// clusterRoutes are answered to a caller with no client certificate, each
// named by its method and path.
func clusterRoutes(node *cdsha.Node) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"GET /ha/status":   reportJSON(node.Status),
		"GET /ha/pins":     reportPinDecree(node),
		"GET /ha/decrees":  reportJSON(node.Decrees),
		"POST /ha/decrees": takeDecree(node),
	}
}

// maxDecreeBody bounds a posted decree, the largest being a pin decree of an
// image roll.
const maxDecreeBody = 1 << 20

// takeDecree hands the decree an operator posts to this replica to the
// cluster, and answers what the cluster made of it.
func takeDecree(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := node.ClockError(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		body, err := readutil.ReadAll(r.Body, maxDecreeBody)
		if err != nil {
			http.Error(w, "cds-ha: the posted decree: "+err.Error(), http.StatusBadRequest)
			return
		}
		signed, err := cdsdecree.Parse(body)
		if err != nil {
			http.Error(w, "cds-ha: the posted decree: "+err.Error(), http.StatusBadRequest)
			return
		}
		delivered, err := node.TakeDecree(signed)
		if err != nil {
			status := http.StatusBadRequest
			if fault := node.ClockError(); fault != nil {
				status = http.StatusServiceUnavailable
				err = fault
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, delivered)
	}
}

func reportJSON[T any](read func() T) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, read())
	}
}

// reportPinDecree serves the pin decree the cluster applied, as the operator
// signed it, and nothing while it applied none.
func reportPinDecree(node *cdsha.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		applied := node.ClusterState().PinsDecree
		if applied == nil {
			http.Error(w, "cds-ha: this cluster has applied no decree pinning its CDS images", http.StatusNotFound)
			return
		}
		writeJSON(w, applied)
	}
}

// writeJSON answers with the whole report or with nothing: an encoding that
// failed half way would otherwise be a 200 carrying a truncated document.
func writeJSON(w http.ResponseWriter, report any) {
	body, err := json.Marshal(report)
	if err != nil {
		slog.Error("cds-ha: this replica could not encode what it reports", "error", err)
		http.Error(w, "cds-ha: this replica could not encode what it reports", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// haGate refuses every route but servedUnjoined while this replica may not
// serve its cluster: it must not issue a leaf, release a secret or hand out
// policy the cluster has moved past.
func haGate(serving func() cdsha.Serving, clockError func() error, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/ha/decrees" {
			if err := clockError(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		if !servedUnjoined(r.URL.Path) || r.URL.Path == "/readyz" {
			if status := serving(); !status.OK {
				http.Error(w, status.Reason, http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func servedUnjoined(path string) bool {
	switch path {
	case "/healthz",
		"/readyz",
		"/metrics",
		"/ha/status",
		"/ha/pins",
		"/ha/decrees":
		return true
	}
	return false
}

// answerWhileJoining serves the client port with health, metrics and the
// cluster routes alone, attested as the full server is. The operator reads an
// unjoined replica's member id and mesh CA there, and posts the Genesis decree
// it then acts on. stop returns once the port is free for the full server.
func (r *clusterCDS) answerWhileJoining(cfg config) (stop func(), err error) {
	server := newHTTPServer(clientAddress(cfg), joiningMux(r.ClusterRoutes()), cfg)
	// A replica holding no mesh CA verifies no client chain.
	tlsCfg, _, err := armtls.NewServerTLSConfig(servingConfig(cfg, nil))
	if err != nil {
		return nil, fmt.Errorf("cds-ha: the attested server a replica answers on while it joins: %w", err)
	}
	server.TLSConfig = tlsCfg
	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			slog.Error("cds-ha: this replica answers nothing while it joins its cluster", "error", err)
		}
	}()
	return func() {
		closing, done := context.WithTimeout(context.Background(), joiningShutdown)
		defer done()
		_ = server.Shutdown(closing)
		<-served
	}, nil
}

// joiningShutdown bounds closing the pre-join listener, which frees the
// client port for the full server.
const joiningShutdown = 5 * time.Second

// joiningMux is what a replica answers before it joins its cluster: the
// routes servedUnjoined names, and a retryable refusal everywhere else.
func joiningMux(cluster map[string]http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	// Never ready: whoever probes an unjoined replica must not put it in front
	// of a client.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cds-ha: this replica has not joined its cluster", http.StatusServiceUnavailable)
	})
	for route, handler := range cluster {
		mux.HandleFunc(route, handler)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cds-ha: this replica has not joined its cluster", http.StatusServiceUnavailable)
	})
	return mux
}
