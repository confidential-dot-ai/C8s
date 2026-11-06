package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifierNeverAttestsOrAcceptsUnsupportedPolicy(t *testing.T) {
	for _, v := range []struct{ path, body string }{{"/attest", `{}`}, {"/verify", `{"platform":"sev-snp","params":{}}`}, {"/verify", `{"platform":"tdx"}`}, {"/verify", `{"platform":"tdx","params":{"allow_debug":true}}`}} {
		w := httptest.NewRecorder()
		verifyTDX(w, httptest.NewRequest("POST", v.path, strings.NewReader(v.body)))
		if w.Code < 400 {
			t.Fatalf("unsupported operation accepted: %s", v.path)
		}
	}
}
