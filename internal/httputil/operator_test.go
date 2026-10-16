package httputil

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func TestRefuseOperatorToken(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"spent", fmt.Errorf("x: %w", operatorauth.ErrTokenReused), http.StatusConflict, operatorauth.ErrTokenReused.Error()},
		{"before start", fmt.Errorf("%w: detail", operatorauth.ErrTokenBeforeStart), http.StatusUnauthorized, operatorauth.ErrTokenBeforeStart.Error()},
		{"not recorded", fmt.Errorf("%w: disk full", operatorauth.ErrTokenNotRecorded), http.StatusServiceUnavailable, operatorauth.ErrTokenNotRecorded.Error()},
		{"bad signature", errors.New("signature invalid"), http.StatusUnauthorized, "unauthorized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			RefuseOperatorToken(w, tc.err)
			if body := strings.TrimSpace(w.Body.String()); w.Code != tc.wantCode || body != tc.wantBody {
				t.Fatalf("RefuseOperatorToken(%v) = %d %q, want %d %q", tc.err, w.Code, body, tc.wantCode, tc.wantBody)
			}
		})
	}
}
