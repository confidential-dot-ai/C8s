package snpaccept

import (
	"io"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
)

// NativeMetadataToken is a synthetic fixture credential for the private guest
// loopback listener. The host pipe invokes the real metadata service using an
// independent, process-local token. Neither token authorizes production access.
const NativeMetadataToken = "native-current-state-fixture-only"

// WithMetadata adds exactly the two current-state routes to the owned storage
// tunnel. Namespace and paths are fixed by the measured launch, not request
// parameters. Existing object/WAL fixture routes retain their implementation.
func (r *Relay) WithMetadata(namespace string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		method := ""
		switch q.URL.Path {
		case metadatapilot.StateReadPath:
			method = "STATE_READ"
		case metadatapilot.StateCommitPath:
			method = "STATE_COMMIT"
		default:
			r.ServeHTTP(w, q)
			return
		}
		if q.Method != http.MethodPost || q.URL.RawQuery != "" || q.Header.Get("X-CDS-Namespace") != namespace || q.Header.Get("Authorization") != "Bearer "+NativeMetadataToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, q.Body, metadatapilot.MaxTransactionBytes))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := r.Exchange(q.Context(), StorageRequest{Method: method, Path: "/pilot/" + namespace + "/metadata" + q.URL.Path, Data: b})
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.Status)
		_, _ = w.Write(response.Data)
	})
}
