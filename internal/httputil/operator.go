package httputil

import (
	"errors"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// RefuseOperatorToken answers a request whose operator token was refused: 409
// for a spent token, 503 when CDS could not record it as spent, 401 otherwise.
// The body is always plain text: the secrets CLI tells this 409 from an
// occupied-path one by its Content-Type.
func RefuseOperatorToken(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, operatorauth.ErrTokenReused):
		http.Error(w, operatorauth.ErrTokenReused.Error(), http.StatusConflict)
	case errors.Is(err, operatorauth.ErrTokenBeforeStart):
		http.Error(w, operatorauth.ErrTokenBeforeStart.Error(), http.StatusUnauthorized)
	case errors.Is(err, operatorauth.ErrTokenNotRecorded):
		http.Error(w, operatorauth.ErrTokenNotRecorded.Error(), http.StatusServiceUnavailable)
	default:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}
