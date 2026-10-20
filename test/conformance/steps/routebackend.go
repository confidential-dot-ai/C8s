package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/cucumber/godog"
)

// echoPort is where a pod's echo API listens, over TLS under the leaf it
// holds.
const echoPort = 40443

// echoServer answers every request with what it received, as JSON, under
// the pod's leaf, read again for each connection so that a renewal never
// leaves it serving an expired one. It listens once the leaf is there.
const echoServer = `
import http.server, json, os, socket, ssl, sys, time
crt, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
while not (os.path.exists(crt) and os.path.exists(key)):
    time.sleep(0.5)
class Handler(http.server.BaseHTTPRequestHandler):
    def handle_one_request(self):
        self.raw_requestline = self.rfile.readline(65537)
        if not self.raw_requestline or not self.parse_request():
            return
        body = json.dumps({"pod": socket.gethostname(), "target": self.path,
                           "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET
    def get_request(self):
        sock, addr = self.socket.accept()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        return ctx.wrap_socket(sock, server_side=True), addr
try:
    Server(("::", port), Handler).serve_forever()
except OSError:
    Server.address_family = socket.AF_INET
    Server(("", port), Handler).serve_forever()
`

// echo is what a pod's echo API answered: the request it received.
type echo struct {
	Pod     string            `json:"pod"`
	Target  string            `json:"target"`
	Headers map[string]string `json:"headers"`
}

func registerRouteBackends(sc *godog.ScenarioContext) {
	sc.Step(`^"([^"]*)" serves an echo API under the leaf it holds$`, servesEcho)
	sc.Step(`^the route manifest routes path "([^"]*)" by (exact|prefix) match on host "([^"]*)" to "([^"]*)" as workload "([^"]*)"$`, manifestRoutesToWorkload)
	sc.Step(`^the router has applied that route manifest$`, func(ctx context.Context) error {
		w := getWorld(ctx)
		if len(w.routes.pending) == 0 {
			return errors.New("the scenario has described no route manifest")
		}
		return w.applyRoutes(w.routes.pending)
	})
	sc.Step(`^a client requests path "([^"]*)" on host "([^"]*)" through the router with X-Forwarded-For "([^"]*)"$`, func(ctx context.Context, path, host, forwarded string) error {
		w := getWorld(ctx)
		return w.routerGet(path, "Host: "+w.routeHost(host), "X-Forwarded-For: "+forwarded)
	})
	sc.Step(`^"([^"]*)" answers that request through the router$`, answersThroughRouter)
	sc.Step(`^the router answers that request itself$`, routerAnswersItself)
	sc.Step(`^the request "([^"]*)" received has the request target "([^"]*)"$`, func(ctx context.Context, name, target string) error {
		return getWorld(ctx).echoed(name, "request target", func(e *echo) (string, string) { return e.Target, target })
	})
	sc.Step(`^the request "([^"]*)" received has the Host of host "([^"]*)"$`, func(ctx context.Context, name, host string) error {
		w := getWorld(ctx)
		return w.echoed(name, "Host", func(e *echo) (string, string) { return e.Headers["host"], w.routeHost(host) })
	})
	sc.Step(`^the request "([^"]*)" received has X-Forwarded-Proto "([^"]*)"$`, func(ctx context.Context, name, proto string) error {
		return getWorld(ctx).echoed(name, "X-Forwarded-Proto", func(e *echo) (string, string) { return e.Headers["x-forwarded-proto"], proto })
	})
	sc.Step(`^the request "([^"]*)" received has X-Forwarded-For "([^"]*)" followed by its X-Real-IP$`, func(ctx context.Context, name, prefix string) error {
		return getWorld(ctx).echoed(name, "X-Forwarded-For", func(e *echo) (string, string) {
			return e.Headers["x-forwarded-for"], prefix + ", " + e.Headers["x-real-ip"]
		})
	})
}

func servesEcho(ctx context.Context, name string) error {
	w := getWorld(ctx)
	p, err := w.undeployed(name)
	if err != nil {
		return err
	}
	paths, err := w.be.call("cert_paths")
	if err != nil {
		return err
	}
	crt, key, ok := strings.Cut(paths, "\n")
	if !ok {
		return fmt.Errorf("cert_paths answered %q", paths)
	}
	p.containers[0].command = []string{"python3", "-c", echoServer, crt, key, strconv.Itoa(echoPort)}
	return nil
}

// manifestRoutesToWorkload adds a route to the manifest the scenario will
// apply: a workload backend at the pod's address, naming the workload entry
// as the scenario wrote it. The address is no evidence of identity (B2);
// the name is.
func manifestRoutesToWorkload(ctx context.Context, path, match, host, name, workload string) error {
	w := getWorld(ctx)
	p, err := w.pod(name)
	if err != nil {
		return err
	}
	if !p.deployed {
		return fmt.Errorf("%q is not deployed; a route names its address", name)
	}
	ips, _, err := w.podIPs(p)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return fmt.Errorf("%q has no address", name)
	}
	if w.routes.pending == nil {
		w.routes.pending = map[string]any{}
	}
	h := w.routeHost(host)
	entry, _ := w.routes.pending[h].(map[string]any)
	if entry == nil {
		entry = map[string]any{"routes": []any{}}
	}
	entry["routes"] = append(entry["routes"].([]any), map[string]any{
		"path":    path,
		"match":   match,
		"backend": map[string]any{"address": net.JoinHostPort(ips[0], strconv.Itoa(echoPort)), "workload": w.writtenName(workload)},
	})
	w.routes.pending[h] = entry
	return nil
}

// echoOf reads the router's last answer as the echo of the pod named.
func (w *world) echoOf(name string) (*echo, error) {
	a, err := w.routerAnswer()
	if err != nil {
		return nil, err
	}
	var e echo
	if a.status != http.StatusOK || json.Unmarshal(a.body, &e) != nil || e.Pod == "" {
		return nil, fmt.Errorf("the router answered %d, not an echo:\n%s", a.status, tail(string(a.body), 5))
	}
	if e.Pod != name {
		return nil, fmt.Errorf("%q answered, not %q", e.Pod, name)
	}
	return &e, nil
}

func answersThroughRouter(ctx context.Context, name string) error {
	_, err := getWorld(ctx).echoOf(name)
	return err
}

// routerAnswersItself: 200, and no echo API wrote the body.
func routerAnswersItself(ctx context.Context) error {
	w := getWorld(ctx)
	a, err := w.routerAnswer()
	if err != nil {
		return err
	}
	var e echo
	if json.Unmarshal(a.body, &e) == nil && e.Pod != "" {
		return fmt.Errorf("the request reached %q", e.Pod)
	}
	if a.status != http.StatusOK {
		return fmt.Errorf("the router answered %d, not 200:\n%s", a.status, tail(string(a.body), 5))
	}
	return nil
}

func (w *world) echoed(name, what string, got func(*echo) (string, string)) error {
	e, err := w.echoOf(name)
	if err != nil {
		return err
	}
	if have, want := got(e); have != want {
		return fmt.Errorf("the request %q received has %s %q, not %q", name, what, have, want)
	}
	return nil
}
