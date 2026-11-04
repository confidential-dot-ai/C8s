package steps

import (
	"strings"
	"testing"
)

func TestRefusedByEndpoint(t *testing.T) {
	for _, tc := range []struct {
		r    dialReport
		want string // empty: refused by the endpoint
	}{
		{dialReport{TLS: true, Error: "remote error: tls: bad certificate"}, ""},
		{dialReport{TLS: false, Error: "dial tcp 10.0.0.2:40080: connect: connection refused"}, "tls"},
		{dialReport{TLS: true, Status: 200, Body: "hello"}, "status"},
		{dialReport{TLS: true, Error: "EOF"}, "alert"},
	} {
		err := refusedByEndpoint(tc.r)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("refusedByEndpoint(%+v) = %v, want a refusal", tc.r, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("refusedByEndpoint(%+v) = %v, want an error naming %q", tc.r, err, tc.want)
		}
	}
}
