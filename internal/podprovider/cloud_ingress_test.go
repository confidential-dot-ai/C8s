package podprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type ingressTransportFunc func(*http.Request) (*http.Response, error)

func (f ingressTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestCloudIngressUsesFrozenRuleAndRecoveryKey(t *testing.T) {
	rule := ingress{Name: "app-8080", Port: 8080}
	var calls int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/instances/i-one/ingress" || r.Header.Get("Idempotency-Key") != "frozen-rule-key" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Api-Version") != "2026-10-15" {
			t.Error("ingress request lost its authenticated frozen identity")
		}
		var got ingress
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != rule {
			t.Errorf("ingress request differs from frozen rule: %v", err)
		}
		in := instance{ID: "i-one", Network: instanceNetwork{Ingress: []ingress{rule}, IngressUpdating: calls == 1}}
		if calls == 1 {
			w.WriteHeader(http.StatusAccepted)
		}
		_ = json.NewEncoder(w).Encode(in)
	}))
	defer srv.Close()
	c := newCloudClient(&Config{CloudURL: srv.URL, token: "test-token"})
	c.http.Transport = srv.Client().Transport
	for i := 0; i < 2; i++ {
		in, err := c.AddIngress(context.Background(), "i-one", "frozen-rule-key", rule)
		if err != nil || in.ID != "i-one" || len(in.Network.Ingress) != 1 || in.Network.Ingress[0] != rule || in.Network.IngressUpdating != (i == 0) {
			t.Fatalf("ingress operation %d lost pending/applied state: %v %v", i, in, err)
		}
	}
	if calls != 2 {
		t.Fatalf("ingress replay calls = %d", calls)
	}
}

func TestCloudIngressRejectsIncompleteIntentBeforeHTTP(t *testing.T) {
	c := newCloudClient(&Config{CloudURL: "https://unused.invalid", token: "test-token"})
	calls := 0
	c.http.Transport = ingressTransportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected HTTP request")
	})
	for _, tc := range []struct {
		id, key string
		rule    ingress
	}{
		{"", "key", ingress{Name: "app", Port: 80}},
		{"i-one", "", ingress{Name: "app", Port: 80}},
		{"i-one", "key", ingress{Port: 80}},
		{"i-one", "key", ingress{Name: "app", Port: 0}},
		{"i-one", "key", ingress{Name: "app", Port: 65536}},
	} {
		if in, err := c.AddIngress(context.Background(), tc.id, tc.key, tc.rule); err == nil || in != nil || calls != 0 {
			t.Fatal("incomplete ingress intent reached the network")
		}
	}
}
