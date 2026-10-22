package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeACME is a minimal RFC 8555 directory: nonce, account, multi-identifier
// orders (one authorization per identifier), http-01 validation against
// challengeBase, finalize signing with the test CA. JWS signatures are not
// verified; payloads are decoded only.
type fakeACME struct {
	t             *testing.T
	ca            *testCA
	challengeBase string // base URL serving /.well-known/acme-challenge/
	srv           *httptest.Server

	// noHTTP01 makes every authorization offer only a dns-01 challenge;
	// failNewOrder and failFinalize refuse those steps terminally (4xx —
	// the acme client retries 5xx with backoff).
	noHTTP01     bool
	failNewOrder bool
	// onNewOrder observes each new-order request (front-door race test).
	onNewOrder   func()
	failFinalize bool
	// rateLimitNewOrder refuses every order with RFC 8555 rateLimited.
	rateLimitNewOrder bool

	mu         sync.Mutex
	domains    map[string][]string // order id -> identifier values
	authzValid map[string]bool     // authz id "<order>-<i>" -> validated
	certs      map[string][]byte   // order id -> chain PEM
	nextID     int
	validated  []string // tokens fetched from the challenge server
}

func newFakeACME(t *testing.T, ca *testCA, challengeBase string) *fakeACME {
	f := &fakeACME{
		t:             t,
		ca:            ca,
		challengeBase: challengeBase,
		domains:       map[string][]string{},
		authzValid:    map[string]bool{},
		certs:         map[string][]byte{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeACME) directoryURL() string { return f.srv.URL + "/dir" }

// jwsPayload decodes the JWS payload of a POST body.
func jwsPayload(t *testing.T, r *http.Request) []byte {
	t.Helper()
	var env struct {
		Payload string `json:"payload"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("not a JWS body: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func (f *fakeACME) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "nonce-1")
	base := f.srv.URL
	path := r.URL.Path
	writeJSON := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case path == "/dir":
		writeJSON(http.StatusOK, map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
		})
	case path == "/nonce":
		w.WriteHeader(http.StatusOK)
	case path == "/acct":
		w.Header().Set("Location", base+"/acct/1")
		writeJSON(http.StatusCreated, map[string]string{"status": "valid"})
	case path == "/order":
		if f.onNewOrder != nil {
			f.onNewOrder()
		}
		if f.failNewOrder {
			http.Error(w, "boom", http.StatusBadRequest)
			return
		}
		if f.rateLimitNewOrder {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"type":   "urn:ietf:params:acme:error:rateLimited",
				"detail": "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s",
			})
			return
		}
		var req struct {
			Identifiers []struct{ Type, Value string } `json:"identifiers"`
		}
		if err := json.Unmarshal(jwsPayload(f.t, r), &req); err != nil || len(req.Identifiers) == 0 {
			http.Error(w, "bad order", http.StatusBadRequest)
			return
		}
		f.nextID++
		id := fmt.Sprint(f.nextID)
		for _, ident := range req.Identifiers {
			f.domains[id] = append(f.domains[id], ident.Value)
		}
		w.Header().Set("Location", base+"/order/"+id)
		writeJSON(http.StatusCreated, f.orderJSON(id))
	case strings.HasPrefix(path, "/order/"):
		writeJSON(http.StatusOK, f.orderJSON(strings.TrimPrefix(path, "/order/")))
	case strings.HasPrefix(path, "/authz/"):
		id := strings.TrimPrefix(path, "/authz/")
		status := "pending"
		if f.authzValid[id] {
			status = "valid"
		}
		challengeType := "http-01"
		if f.noHTTP01 {
			challengeType = "dns-01"
		}
		writeJSON(http.StatusOK, map[string]any{
			"status":     status,
			"identifier": map[string]string{"type": "dns", "value": f.authzDomain(id)},
			"challenges": []map[string]string{{
				"type":   challengeType,
				"url":    base + "/challenge/" + id,
				"token":  "token-" + id,
				"status": status,
			}},
		})
	case strings.HasPrefix(path, "/challenge/"):
		id := strings.TrimPrefix(path, "/challenge/")
		token := "token-" + id
		// Validate over HTTP like a real CA (without holding the lock),
		// retrying briefly while the challenge listener is still binding.
		f.mu.Unlock()
		var resp *http.Response
		var err error
		var keyAuth []byte
		for deadline := time.Now().Add(5 * time.Second); ; {
			resp, err = http.Get(f.challengeBase + challengePrefix + token)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err == nil {
			keyAuth, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		f.mu.Lock()
		if err != nil || resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(keyAuth), token+".") {
			http.Error(w, "challenge fetch failed", http.StatusBadRequest)
			return
		}
		f.validated = append(f.validated, token)
		f.authzValid[id] = true
		writeJSON(http.StatusOK, map[string]string{"type": "http-01", "url": base + path, "token": token, "status": "valid"})
	case strings.HasPrefix(path, "/finalize/"):
		if f.failFinalize {
			http.Error(w, "boom", http.StatusBadRequest)
			return
		}
		id := strings.TrimPrefix(path, "/finalize/")
		if !f.orderReady(id) {
			http.Error(w, "authz not valid", http.StatusForbidden)
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.Unmarshal(jwsPayload(f.t, r), &req); err != nil {
			http.Error(w, "bad finalize", http.StatusBadRequest)
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(req.CSR)
		if err != nil {
			http.Error(w, "bad csr encoding", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		// The CSR must name exactly the ordered identifier set.
		if !sameDomainSet(csr.DNSNames, f.domains[id]) {
			http.Error(w, "csr names the wrong domain set", http.StatusBadRequest)
			return
		}
		f.certs[id] = f.ca.sign(f.t, csr)
		w.Header().Set("Location", f.srv.URL+"/order/"+id)
		writeJSON(http.StatusOK, f.orderJSON(id))
	case strings.HasPrefix(path, "/cert/"):
		id := strings.TrimPrefix(path, "/cert/")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(f.certs[id])
	default:
		http.NotFound(w, r)
	}
}

// authzDomain resolves "<order>-<i>" to its identifier; called with f.mu held.
func (f *fakeACME) authzDomain(id string) string {
	order, idx, ok := strings.Cut(id, "-")
	if !ok {
		return ""
	}
	i, err := strconv.Atoi(idx)
	if err != nil || i < 0 || i >= len(f.domains[order]) {
		return ""
	}
	return f.domains[order][i]
}

// orderReady reports whether every authorization of the order validated;
// called with f.mu held.
func (f *fakeACME) orderReady(id string) bool {
	for i := range f.domains[id] {
		if !f.authzValid[fmt.Sprintf("%s-%d", id, i)] {
			return false
		}
	}
	return len(f.domains[id]) > 0
}

// orderJSON reflects an order's state; called with f.mu held.
func (f *fakeACME) orderJSON(id string) map[string]any {
	base := f.srv.URL
	var identifiers []map[string]string
	var authz []string
	for i, d := range f.domains[id] {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": d})
		authz = append(authz, fmt.Sprintf("%s/authz/%s-%d", base, id, i))
	}
	o := map[string]any{
		"status":         "pending",
		"identifiers":    identifiers,
		"authorizations": authz,
		"finalize":       base + "/finalize/" + id,
	}
	if f.orderReady(id) {
		o["status"] = "ready"
	}
	if _, issued := f.certs[id]; issued {
		o["status"] = "valid"
		o["certificate"] = base + "/cert/" + id
	}
	return o
}
