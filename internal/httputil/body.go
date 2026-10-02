// Package httputil holds small HTTP-handler utilities shared across C8s
// internal packages.
package httputil

import (
	"errors"
	"net/http"

	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// ReadCappedBody reads up to maxBytes from r.Body. On read failure it
// writes 400; if the body exceeds maxBytes it writes 413. On either
// failure it returns (nil, false). On success it returns the body
// bytes and true.
func ReadCappedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, bool) {
	body, err := readutil.ReadAll(r.Body, maxBytes)
	if errors.Is(err, readutil.ErrTooLarge) {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}
