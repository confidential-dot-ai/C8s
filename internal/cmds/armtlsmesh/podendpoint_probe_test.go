//go:build linux

package armtlsmesh

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// startProbeServer runs the endpoint's probe server over targets and returns
// its base URL.
func startProbeServer(t *testing.T, targets probeTargets) string {
	t.Helper()
	e := &podEndpoint{
		logger:      discardLogger(),
		probes:      targets,
		probeClient: newProbeClient(),
	}
	e.initialized.Store(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := e.probeServer()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

// startProbedApp serves status and body on loopback, counting the paths it was
// asked for.
func startProbedApp(t *testing.T, status int, body string) (port int32, asked *[]string) {
	t.Helper()
	var paths []string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(app.Close)
	parsed, err := url.Parse(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	return int32(number), &paths
}

// probe reports the status and body of one request to the health port.
func probe(t *testing.T, base, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// A rewritten application probe reaches the application and comes back as its
// status code alone: the node learns nothing the application answered with.
func TestForwardedProbeCarriesTheStatusCodeOnly(t *testing.T) {
	port, asked := startProbedApp(t, http.StatusOK, "model-weights-are-loaded")
	path := workloadclaims.MeshProbePath(port, "/healthz")
	targets, err := probeTargetsFor([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	base := startProbeServer(t, targets)

	status, body := probe(t, base, path)

	if status != http.StatusOK {
		t.Fatalf("GET %s = %d, want %d", path, status, http.StatusOK)
	}
	if body != "" {
		t.Fatalf("GET %s answered %q, want an empty body", path, body)
	}
	if len(*asked) != 1 || (*asked)[0] != "/healthz" {
		t.Fatalf("the application was asked for %v, want one request for /healthz", *asked)
	}
}

// An unready application is reported unready: the kubelet sees the code the
// application would have given it.
func TestForwardedProbeReportsTheApplicationStatus(t *testing.T) {
	port, _ := startProbedApp(t, http.StatusServiceUnavailable, "")
	path := workloadclaims.MeshProbePath(port, "/readyz")
	targets, err := probeTargetsFor([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	base := startProbeServer(t, targets)

	if status, _ := probe(t, base, path); status != http.StatusServiceUnavailable {
		t.Fatalf("GET %s = %d, want %d", path, status, http.StatusServiceUnavailable)
	}
}

// The health port is plaintext and reachable from the node, so it forwards the
// probe targets the injector rendered and refuses every other path: no caller
// can turn it into a reader of the pod's loopback.
func TestForwardedProbeRefusesAnUnrenderedTarget(t *testing.T) {
	port, asked := startProbedApp(t, http.StatusOK, "")
	rendered := workloadclaims.MeshProbePath(port, "/healthz")
	targets, err := probeTargetsFor([]string{rendered})
	if err != nil {
		t.Fatal(err)
	}
	base := startProbeServer(t, targets)

	for _, path := range []string{
		workloadclaims.MeshProbePath(port, "/metrics"),
		workloadclaims.MeshProbePath(port+1, "/healthz"),
		workloadclaims.MeshProbePrefix,
		workloadclaims.MeshProbePrefix + "8080",
		rendered + "/..%2fmetrics",
	} {
		if status, _ := probe(t, base, path); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want %d", path, status, http.StatusNotFound)
		}
	}
	if len(*asked) != 0 {
		t.Fatalf("the application was asked for %v, want nothing", *asked)
	}
}

// A target the endpoint cannot serve fails before it binds: a mesh port would
// forward the probe into the endpoint itself, and a malformed path names no
// application port.
func TestProbeTargetsRefuseWhatCannotBeForwarded(t *testing.T) {
	for _, path := range []string{
		workloadclaims.MeshProbePath(workloadclaims.MeshHealthPort, "/readyz"),
		workloadclaims.MeshProbePath(workloadclaims.MeshInboundPort, "/healthz"),
		workloadclaims.MeshProbePath(workloadclaims.MeshOutboundPort, "/healthz"),
		"/readyz",
		workloadclaims.MeshProbePrefix + "8080",
		workloadclaims.MeshProbePrefix + "http/healthz",
		workloadclaims.MeshProbePrefix + "0/healthz",
		workloadclaims.MeshProbePrefix + "70000/healthz",
	} {
		if _, err := probeTargetsFor([]string{path}); err == nil {
			t.Errorf("probeTargetsFor(%q) = nil error, want a refusal", path)
		}
	}
}

// The endpoint takes its probe targets from the environment the injector sets,
// and refuses one it cannot forward before it binds anything.
func TestPodEndpointRefusesAnUnforwardableProbeFromTheEnvironment(t *testing.T) {
	volume := testVolume(t)
	t.Setenv(workloadclaims.MeshProbesEnv, workloadclaims.MeshProbePath(workloadclaims.MeshInboundPort, "/healthz"))
	cmd := newPodEndpointCommand()
	cmd.SetArgs([]string{
		"--cert-path", volume.dir + "/" + volume.chainName,
		"--key-path", volume.dir + "/" + volume.keyName,
		"--ca-path", volume.dir + "/" + volume.caName,
	})

	err := cmd.Execute()

	if err == nil {
		t.Fatal("the endpoint started with a probe target on a mesh port")
	}
	if !strings.Contains(err.Error(), "mesh port") {
		t.Errorf("error %q does not report the refused probe target", err)
	}
}
