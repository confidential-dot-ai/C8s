package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	fixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-recovery"
)

func TestReadOnlyReceiptCannotTriggerOrRepeatFaults(t *testing.T) {
	c := &controller{receipt: fixture.Receipt{Schema: 1, Scope: fixture.Scope, State: "baseline", Phases: []fixture.Phase{}}}
	before := c.receipt
	h := c.handler(http.NotFoundHandler())
	for _, req := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, fixture.ReceiptPath, http.StatusOK},
		{http.MethodPost, fixture.ReceiptPath, http.StatusMethodNotAllowed},
		{http.MethodPost, "/restart", http.StatusNotFound},
		{http.MethodPost, "/v1/assign", http.StatusNotFound},
		{http.MethodGet, "/etc/confai/pubkey", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, httptest.NewRequest(req.method, req.path, strings.NewReader(`{"unit":"other.service"}`)))
		if response.Code != req.status {
			t.Fatalf("%s %s returned %d", req.method, req.path, response.Code)
		}
		if !reflect.DeepEqual(c.receipt, before) {
			t.Fatal("HTTP observation changed fixture state")
		}
	}
}

func TestRetainedPolicyChangesCannotHideBehindRevision(t *testing.T) {
	a, err := stableHistory([]byte(`{"revision":1,"policy":{"version":1,"document":{"rules":"new"},"digest":"a"},"histories":{"old":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := stableHistory([]byte(`{"revision":2,"policy":{"version":1,"document":{"rules":"new"},"digest":"a"},"histories":{"old":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("revision alone changed retained state")
	}
	for _, bad := range []string{
		`{"revision":2,"policy":{"version":1,"document":{"rules":"old"},"digest":"b"},"histories":{"old":true}}`,
		`{"revision":2,"histories":{"old":true}}`,
		`{"revision":2,"policy":{"version":1,"document":{"rules":"new"},"digest":"a"},"histories":{}}`,
	} {
		got, err := stableHistory([]byte(bad))
		if err != nil {
			t.Fatal(err)
		}
		if a == got {
			t.Fatal("lost policy or history was hidden")
		}
	}
}
