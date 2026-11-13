package cdsgenesis

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// C-ID: an answer naming another chain, or none, is refused; the pin is sent.
func TestClientHoldsAnswersToThePin(t *testing.T) {
	for _, tc := range []struct {
		answer string
		ok     bool
	}{{"3:abc", true}, {"0:other", false}, {"", false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(Header) != "3:abc" {
				t.Errorf("the pin was not sent: %q", r.Header.Get(Header))
			}
			if tc.answer != "" {
				w.Header().Set(Header, tc.answer)
			}
		}))
		resp, err := Client(srv.Client(), "3:abc").Get(srv.URL)
		srv.Close()
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrOtherGenesis)) {
			t.Errorf("answer %q: %v", tc.answer, err)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}
