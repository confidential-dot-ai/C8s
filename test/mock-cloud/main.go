// mock-cloud is a fake Cloud instance API for integration testing: the
// instance subset the Pod CVM provider calls (internal/podprovider/cloud.go),
// plus a control surface under /control that sets how the API answers and
// lists the calls it received. It starts no VM, so no instance ever serves a
// pod status endpoint. No authentication beyond a bearer token being present;
// use only in test environments.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
)

// The size every instance reports, whatever size the create names.
const (
	vcpus     = 4
	memoryGiB = 8
	// endpointHost is a documentation address (TEST-NET-3): public, and
	// answered by nothing.
	endpointHost = "203.0.113.5"
)

type ingress struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type endpoint struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type image struct {
	Family  string `json:"family"`
	Version string `json:"version"`
}

type compute struct {
	VCPUs     int64 `json:"vcpus"`
	MemoryGiB int64 `json:"memoryGiB"`
}

type boot struct {
	Count int64 `json:"count"`
}

type instance struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Tee       string            `json:"tee"`
	Labels    map[string]string `json:"labels"`
	Endpoints []endpoint        `json:"endpoints"`
	Image     image             `json:"image"`
	Compute   compute           `json:"compute"`
	Boot      boot              `json:"boot"`
	key       string
}

type createRequest struct {
	Image   string            `json:"image"`
	Tee     string            `json:"tee"`
	Labels  map[string]string `json:"labels"`
	Network struct {
		Ingress []ingress `json:"ingress"`
	} `json:"network"`
}

// problem is a refusal the API answers a create with.
type problem struct {
	Status     int    `json:"status"`
	Code       string `json:"code"`
	RetryAfter string `json:"retryAfter,omitempty"`
}

// behaviour is how the API answers until it is replaced; the zero value
// creates every instance running and destroys it on the first delete.
type behaviour struct {
	// Outage answers every API call 503.
	Outage bool `json:"outage,omitempty"`
	// Create refuses every create with this problem.
	Create *problem `json:"create,omitempty"`
	// Status and BootCount are reported for every instance not yet
	// terminated, in place of running and one.
	Status    string `json:"status,omitempty"`
	BootCount int64  `json:"bootCount,omitempty"`
	// Gone makes every instance unknown to lookups.
	Gone bool `json:"gone,omitempty"`
	// ForeignLabels reports every instance under another provider's label.
	ForeignLabels bool `json:"foreignLabels,omitempty"`
	// Lingering accepts a delete and leaves the instance terminating.
	Lingering bool `json:"lingering,omitempty"`
}

// call is one API request as received.
type call struct {
	Method         string          `json:"method"`
	Path           string          `json:"path"`
	IdempotencyKey string          `json:"idempotencyKey,omitempty"`
	Body           json.RawMessage `json:"body,omitempty"`
}

type cloud struct {
	mu        sync.Mutex
	behaviour behaviour
	instances []*instance
	calls     []call
}

func main() {
	addr := ":8080"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v
	}
	slog.Info("mock Cloud listening", "addr", addr)
	if err := http.ListenAndServe(addr, new(cloud).handler()); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

func (c *cloud) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("PUT /control/behaviour", c.setBehaviour)
	mux.HandleFunc("GET /control/calls", c.listCalls)
	mux.HandleFunc("GET /control/instances", c.listInstances)
	mux.HandleFunc("GET /v1/instances", c.api(c.find))
	mux.HandleFunc("POST /v1/instances", c.api(c.create))
	mux.HandleFunc("GET /v1/instances/{id}", c.api(c.get))
	mux.HandleFunc("DELETE /v1/instances/{id}", c.api(c.destroy))
	return mux
}

func (c *cloud) setBehaviour(w http.ResponseWriter, r *http.Request) {
	var b behaviour
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.behaviour = b
}

func (c *cloud) listCalls(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	answer(w, http.StatusOK, append([]call{}, c.calls...))
}

// listInstances is every instance as the cloud holds it, whatever the
// behaviour reports for it.
func (c *cloud) listInstances(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	answer(w, http.StatusOK, append([]*instance{}, c.instances...))
}

// api records the call and applies what every API call shares: the bearer
// token, the outage, and the lock the handler runs under.
func (c *cloud) api(handle func(http.ResponseWriter, *http.Request, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			body = nil
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls = append(c.calls, call{Method: r.Method, Path: r.URL.RequestURI(), IdempotencyKey: r.Header.Get("Idempotency-Key"), Body: body})
		switch {
		case !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "):
			refuse(w, problem{Status: http.StatusUnauthorized, Code: "unauthenticated"})
		case c.behaviour.Outage:
			refuse(w, problem{Status: http.StatusServiceUnavailable, Code: "unavailable"})
		default:
			handle(w, r, body)
		}
	}
}

func (c *cloud) find(w http.ResponseWriter, r *http.Request, _ []byte) {
	items := []instance{}
	key := r.URL.Query().Get("idempotencyKey")
	for _, in := range c.instances {
		if !c.behaviour.Gone && (key == "" || in.key == key) {
			items = append(items, c.reported(in))
		}
	}
	answer(w, http.StatusOK, map[string]any{"items": items})
}

func (c *cloud) create(w http.ResponseWriter, r *http.Request, body []byte) {
	if p := c.behaviour.Create; p != nil {
		refuse(w, *p)
		return
	}
	var req createRequest
	key := r.Header.Get("Idempotency-Key")
	if err := json.Unmarshal(body, &req); err != nil || key == "" {
		refuse(w, problem{Status: http.StatusBadRequest, Code: "invalid_request"})
		return
	}
	in := c.byKey(key)
	if in == nil {
		in = &instance{ID: fmt.Sprintf("i-%04d", len(c.instances)+1), Status: "running", Tee: req.Tee, Labels: req.Labels, key: key}
		in.Image.Family, in.Image.Version, _ = strings.Cut(req.Image, "@")
		in.Compute = compute{VCPUs: vcpus, MemoryGiB: memoryGiB}
		in.Boot.Count = 1
		for i, rule := range req.Network.Ingress {
			in.Endpoints = append(in.Endpoints, endpoint{Name: rule.Name, Host: endpointHost, Port: 30000 + i})
		}
		c.instances = append(c.instances, in)
	}
	answer(w, http.StatusCreated, map[string]any{"items": []instance{c.reported(in)}})
}

func (c *cloud) get(w http.ResponseWriter, r *http.Request, _ []byte) {
	in := c.byID(r.PathValue("id"))
	if in == nil || c.behaviour.Gone {
		refuse(w, problem{Status: http.StatusNotFound, Code: "not_found"})
		return
	}
	answer(w, http.StatusOK, c.reported(in))
}

func (c *cloud) destroy(w http.ResponseWriter, r *http.Request, _ []byte) {
	in := c.byID(r.PathValue("id"))
	if in == nil {
		refuse(w, problem{Status: http.StatusNotFound, Code: "not_found"})
		return
	}
	in.Status = "terminated"
	if c.behaviour.Lingering {
		in.Status = "terminating"
	}
	w.WriteHeader(http.StatusAccepted)
}

func (c *cloud) byID(id string) *instance {
	for _, in := range c.instances {
		if in.ID == id {
			return in
		}
	}
	return nil
}

func (c *cloud) byKey(key string) *instance {
	for _, in := range c.instances {
		if in.key == key {
			return in
		}
	}
	return nil
}

// reported is the instance as the behaviour has the API describe it. An
// instance a delete reached keeps the state the delete left it in.
func (c *cloud) reported(in *instance) instance {
	out := *in
	if in.Status != "running" {
		return out
	}
	if c.behaviour.Status != "" {
		out.Status = c.behaviour.Status
	}
	if c.behaviour.BootCount != 0 {
		out.Boot.Count = c.behaviour.BootCount
	}
	if c.behaviour.ForeignLabels {
		out.Labels = map[string]string{"podcvm-provider": "another-provider"}
	}
	return out
}

func refuse(w http.ResponseWriter, p problem) {
	if p.RetryAfter != "" {
		w.Header().Set("Retry-After", p.RetryAfter)
	}
	answer(w, p.Status, map[string]string{"code": p.Code})
}

func answer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
