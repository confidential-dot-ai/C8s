package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

// config is the compact JSON the pod document passes as the second argument
// of the serve and check modes.
type config struct {
	Role            string      `json:"role,omitempty"`            // "responder", "initiator" or "" for the peer list
	PodUID          string      `json:"podUID"`                    // the pod this workload answers for
	InitiatorPodUID string      `json:"initiatorPodUID,omitempty"` // the one pod a responder accepts a receipt from
	Peers           []string    `json:"peers,omitempty"`           // hosts answering /id on the application port
	Peer            *peerConfig `json:"peer,omitempty"`            // the initiator's one responder
	DNSIPv4         string      `json:"dnsIPv4,omitempty"`         // the public resolver dialled on the wire
	CollectorURL    string      `json:"collectorURL,omitempty"`    // optional best-effort sink of each report
}

type peerConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	PodUID string `json:"podUID"`
}

func parseConfig(raw string) (config, error) {
	var cfg config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// receipt is the inbound mesh call a responder holds for its initiator.
type receipt struct {
	Instance   string  `json:"instance"`
	PodUID     string  `json:"podUID"`
	ReceivedAt float64 `json:"receivedAt"`
}

type checkResult struct {
	OK     bool   `json:"ok"`
	Detail any    `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// checkNames is the order of a probe round; the checker requires exactly
// these to be present.
var checkNames = []string{"peer_mesh", "system_dns", "internet_tcp", "internet_udp_dns", "internet_tcp_dns", "guest_linklocal_denied"}

var instancePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Forbidden destinations: the guest's CDS and status link, the kubelet and
// the metadata address. Reaching any of them is a failed check.
var forbidden = []string{"10.255.254.1:8443", "10.255.254.1:8400", "10.255.254.1:10250", "169.254.169.254:80"}

const guestResolver = "10.255.254.1"

// app is the serve mode: a probe loop and the HTTP report of its results.
type app struct {
	cfg        config
	instance   string
	now        func() float64 // seconds since start, monotonic
	sleep      func(time.Duration)
	transport  http.RoundTripper
	resolvConf string
	out        io.Writer

	mu        sync.Mutex
	checks    map[string]checkResult
	firstPass *float64
	checkedAt *float64
	inbound   *receipt
}

func newApp(raw string) (*app, error) {
	cfg, err := parseConfig(raw)
	if err != nil {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	start := time.Now()
	return &app{cfg: cfg, instance: hex.EncodeToString(id[:]), now: func() float64 { return time.Since(start).Seconds() },
		sleep: time.Sleep, transport: http.DefaultTransport, resolvConf: "/etc/resolv.conf", out: os.Stdout, checks: map[string]checkResult{}}, nil
}

func (a *app) client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: a.transport, Timeout: timeout}
}

// get sends one GET and returns the status and at most limit body bytes.
func (a *app) get(url string, timeout time.Duration, headers map[string]string, limit int64) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.client(timeout).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, body, err
}

func (a *app) peerMesh() (any, error) {
	switch a.cfg.Role {
	case "responder":
		a.mu.Lock()
		r := a.inbound
		a.mu.Unlock()
		if r == nil || a.now()-r.ReceivedAt < 0 || a.now()-r.ReceivedAt > podfixture.Freshness.Seconds() {
			return nil, errors.New("waiting for fresh inbound mesh receipt")
		}
		return map[string]any{"inboundReceipt": r}, nil
	case "initiator":
		peer := a.cfg.Peer
		if peer == nil {
			return nil, errors.New("initiator has no peer")
		}
		endpoint := net.JoinHostPort(peer.Host, strconv.Itoa(peer.Port))
		status, body, err := a.get("http://"+endpoint+"/id", 4*time.Second, map[string]string{"X-Acceptance-Instance": a.instance, "X-Acceptance-Pod": a.cfg.PodUID}, 4096)
		if err != nil {
			return nil, err
		}
		var answer struct {
			Instance string `json:"instance"`
			PodUID   string `json:"podUID"`
		}
		if json.Unmarshal(body, &answer) != nil || status != http.StatusOK || answer.PodUID != peer.PodUID || len(answer.Instance) != 32 || answer.Instance == a.instance {
			return nil, errors.New("expected distinct responder did not answer captured tuple")
		}
		return map[string]any{"endpoint": endpoint, "instance": answer.Instance}, nil
	}
	var found []map[string]any
	for _, host := range a.cfg.Peers {
		endpoint := net.JoinHostPort(host, "8080")
		status, body, err := a.get("http://"+endpoint+"/id", 4*time.Second, nil, 4096)
		if err != nil {
			continue
		}
		var answer struct {
			Instance string `json:"instance"`
		}
		if json.Unmarshal(body, &answer) == nil && status == http.StatusOK && answer.Instance != a.instance {
			found = append(found, map[string]any{"endpoint": endpoint, "instance": answer.Instance})
		}
	}
	if len(found) == 0 {
		return nil, errors.New("no distinct peer answered through the captured tuple")
	}
	return found, nil
}

// recordInbound keeps the first initiator instance that calls a responder
// and refuses every other caller.
func (a *app) recordInbound(caller, callerPod string) bool {
	if a.cfg.Role != "responder" || callerPod != a.cfg.InitiatorPodUID || !instancePattern.MatchString(caller) || caller == a.instance {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inbound != nil && a.inbound.Instance != caller {
		return false
	}
	a.inbound = &receipt{Instance: caller, PodUID: callerPod, ReceivedAt: a.now()}
	return true
}

func (a *app) systemDNS() (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "example.com")
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, ip := range ips {
		set[ip.String()] = true
	}
	addresses := make([]string, 0, len(set))
	for ip := range set {
		addresses = append(addresses, ip)
	}
	sort.Strings(addresses)
	raw, err := os.ReadFile(a.resolvConf)
	if err != nil {
		return nil, err
	}
	var resolvers []string
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "nameserver" && strings.HasPrefix(line, "nameserver ") {
			resolvers = append(resolvers, fields[1])
		}
	}
	if len(addresses) == 0 || len(resolvers) == 0 {
		return nil, errors.New("no system DNS result or resolver")
	}
	for _, value := range resolvers {
		ip := net.ParseIP(value)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || value == guestResolver {
			return nil, errors.New("guest-local DNS configuration")
		}
	}
	return map[string]any{"addresses": addresses, "resolvers": resolvers}, nil
}

func (a *app) internetTCP() (any, error) {
	status, _, err := a.get("https://example.com/", 5*time.Second, nil, 512)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 400 {
		return nil, errors.New("internet HTTPS status " + strconv.Itoa(status))
	}
	return map[string]any{"status": status}, nil
}

// dnsWire sends one A query for example.com to the configured resolver over
// the given transport and requires an answered response.
func (a *app) dnsWire(network string) (any, error) {
	ident := uint16(mathrand.N(65536))
	query := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(query[0:], ident)
	binary.BigEndian.PutUint16(query[2:], 0x100)
	binary.BigEndian.PutUint16(query[4:], 1)
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	conn, err := net.DialTimeout(network, net.JoinHostPort(a.cfg.DNSIPv4, "53"), 4*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return nil, err
	}
	var reply []byte
	if network == "tcp" {
		framed := append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, errors.New("short DNS response")
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size < 12 || size > 8192 {
			return nil, errors.New("invalid DNS response length")
		}
		reply = make([]byte, size)
		if _, err := io.ReadFull(conn, reply); err != nil {
			return nil, errors.New("short DNS response")
		}
	} else {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 8192)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		reply = buf[:n]
	}
	if len(reply) < 12 {
		return nil, errors.New("short DNS response")
	}
	flags, answers := binary.BigEndian.Uint16(reply[2:]), binary.BigEndian.Uint16(reply[6:])
	if binary.BigEndian.Uint16(reply[0:]) != ident || flags&0x8000 == 0 || flags&15 != 0 || answers == 0 {
		return nil, errors.New("DNS response did not answer the query")
	}
	return map[string]any{"resolver": a.cfg.DNSIPv4, "answers": answers}, nil
}

// exclusions dials each forbidden destination and passes only when every
// dial fails.
func (a *app) exclusions() (any, error) {
	var results []map[string]any
	for _, destination := range forbidden {
		conn, err := net.DialTimeout("tcp", destination, time.Second)
		if err == nil {
			conn.Close()
			return nil, errors.New("forbidden destination is reachable: " + destination)
		}
		results = append(results, map[string]any{"destination": destination, "result": failureName(err)})
	}
	return results, nil
}

// failureName names a dial failure the way the report records it.
func failureName(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return "error"
}

// report is the application's state as /report and /ready serve it. The pod
// is ready only with a fresh all-pass round, ReadyAfter past the first pass
// and outside the deliberate dip.
func (a *app) report() map[string]any {
	a.mu.Lock()
	checks := make(map[string]checkResult, len(a.checks))
	for k, v := range a.checks {
		checks[k] = v
	}
	firstPass, checkedAt, inbound := a.firstPass, a.checkedAt, a.inbound
	a.mu.Unlock()
	elapsed := a.now()
	age := -1.0
	if firstPass != nil {
		age = elapsed - *firstPass
	}
	ready := len(checks) > 0 && allOK(checks) && checkedAt != nil && elapsed-*checkedAt >= 0 && elapsed-*checkedAt <= podfixture.Freshness.Seconds() &&
		age >= podfixture.ReadyAfter.Seconds() && !(age >= podfixture.DipStart.Seconds() && age < podfixture.DipEnd.Seconds())
	result := map[string]any{"instance": a.instance, "checks": checks, "firstPass": firstPass, "checkedAt": checkedAt,
		"elapsed": math.Round(elapsed*100) / 100, "uid": os.Getuid(), "podUID": a.cfg.PodUID, "ready": ready}
	if inbound != nil {
		result["inboundReceipt"] = inbound
	}
	return result
}

func allOK(checks map[string]checkResult) bool {
	for _, c := range checks {
		if !c.OK {
			return false
		}
	}
	return true
}

func (a *app) runChecks() map[string]checkResult {
	fns := map[string]func() (any, error){"peer_mesh": a.peerMesh, "system_dns": a.systemDNS, "internet_tcp": a.internetTCP,
		"internet_udp_dns": func() (any, error) { return a.dnsWire("udp") }, "internet_tcp_dns": func() (any, error) { return a.dnsWire("tcp") },
		"guest_linklocal_denied": a.exclusions}
	results := make(map[string]checkResult, len(checkNames))
	for _, name := range checkNames {
		detail, err := fns[name]()
		if err != nil {
			msg := err.Error()
			if len(msg) > 200 {
				msg = msg[:200]
			}
			results[name] = checkResult{Error: msg}
			continue
		}
		results[name] = checkResult{OK: true, Detail: detail}
	}
	return results
}

// probeLoop runs a round every Period, prints the report and posts it to
// the collector when one is configured.
func (a *app) probeLoop() {
	for {
		results := a.runChecks()
		a.mu.Lock()
		a.checks = results
		now := a.now()
		a.checkedAt = &now
		if a.firstPass == nil && allOK(results) {
			first := now
			a.firstPass = &first
		}
		a.mu.Unlock()
		body, _ := json.Marshal(a.report())
		fmt.Fprintln(a.out, string(body))
		if a.cfg.CollectorURL != "" {
			if resp, err := a.client(3*time.Second).Post(a.cfg.CollectorURL, "application/json", strings.NewReader(string(body))); err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
				resp.Body.Close()
			}
		}
		a.sleep(podfixture.Period)
	}
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	status := http.StatusOK
	var body any = map[string]any{"instance": a.instance, "podUID": a.cfg.PodUID}
	if r.URL.Path == "/id" && a.cfg.Role == "responder" && !a.recordInbound(r.Header.Get("X-Acceptance-Instance"), r.Header.Get("X-Acceptance-Pod")) {
		status = http.StatusForbidden
	}
	switch r.URL.Path {
	case "/ready":
		report := a.report()
		body = report
		if !report["ready"].(bool) {
			status = http.StatusServiceUnavailable
		}
	case "/report":
		body = a.report()
	case "/id", "/live":
	default:
		status, body = http.StatusNotFound, map[string]any{}
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
