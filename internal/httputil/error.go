package httputil

import (
	"encoding/json"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// WriteError answers in the C8s error-envelope shape: code is one of
// pkg/types' stable wire identifiers, message is prose for a human.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(types.ErrorResponse{Error: code, Message: message})
}
