//go:build linux

package armtlsmesh

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// boundPort is the port a listener the endpoint bound answers on.
func boundPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address %v is not a TCP address", ln.Addr())
	}
	return addr.Port
}

// expectProbe reads one probe. The endpoint binds the probe port before it
// serves, so the request waits in the listener's backlog and needs no retry.
func expectProbe(t *testing.T, port int, path string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s answered %s", path, resp.Status)
	}
}

// The command refuses to start without the three credential paths it reads,
// and runs the endpoint on the ones it is given.
func TestPodEndpointCommandFlags(t *testing.T) {
	cmd := newPodEndpointCommand()
	for _, flag := range []string{"cert-path", "key-path", "ca-path"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Fatalf("--%s is not a flag of the command", flag)
		}
	}

	cmd.SetArgs([]string{"--cert-path", "/run/certs/tls.crt"})
	cmd.SetOut(nil)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("the command started without --key-path and --ca-path")
	}
	for _, flag := range []string{"key-path", "ca-path"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error %q does not name the missing --%s", err, flag)
		}
	}

	volume := testVolume(t)
	wired := newPodEndpointCommand()
	wired.SetArgs([]string{
		"--cert-path", volume.dir + "/" + volume.chainName,
		"--key-path", "/run/elsewhere/tls.key",
		"--ca-path", volume.dir + "/" + volume.caName,
	})
	err = wired.Execute()
	if err == nil {
		t.Fatal("the command ran with credential paths in two directories")
	}
	if !strings.Contains(err.Error(), "one directory") {
		t.Errorf("error %q does not come from the endpoint the command runs", err)
	}
}

// A capture port already in use stops the endpoint before it serves: a half
// bound endpoint would leave captured traffic unanswered.
func TestRunPodEndpointRefusesATakenPort(t *testing.T) {
	volume := testVolume(t)
	for position := range 3 {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		taken := ln.Addr().(*net.TCPAddr).Port
		ports := []int{0, 0, 0}
		ports[position] = taken
		cfg := podEndpointConfig{
			chainPath: volume.dir + "/" + volume.chainName,
			keyPath:   volume.dir + "/" + volume.keyName,
			caPath:    volume.dir + "/" + volume.caName,
		}
		err = runPodEndpoint(context.Background(), &cfg, ports[0], ports[1], ports[2])
		ln.Close()
		if err == nil {
			t.Fatalf("the endpoint bound port %d while it was in use", taken)
		}
		if want := fmt.Sprintf("listen on port %d", taken); !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not report %q", err, want)
		}
	}
}

// The endpoint serves on its three bound ports until its context is cancelled,
// and reports a clean stop: the pod's ruleset keeps the pod sealed either way.
func TestPodEndpointServesUntilCancelled(t *testing.T) {
	if _, err := ownPodAddresses(); err != nil {
		t.Skipf("no pod address in this namespace: %v", err)
	}
	ca := newMeshCA(t, time.Hour)
	volume := testVolume(t)
	publishSet(t, volume, ca.issue(t, leafSpec{}))
	cfg := podEndpointConfig{
		chainPath: volume.dir + "/" + volume.chainName,
		keyPath:   volume.dir + "/" + volume.keyName,
		caPath:    volume.dir + "/" + volume.caName,
	}
	endpoint, err := newPodEndpoint(&cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	endpoint.credentials.reload(time.Now())

	ctx, cancel := context.WithCancel(context.Background())
	listeners, err := endpoint.bind(ctx, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() {
		stopped <- endpoint.serve(ctx, listeners)
	}()
	expectProbe(t, boundPort(t, listeners.probes), "/startupz")
	expectProbe(t, boundPort(t, listeners.probes), "/readyz")
	for _, captured := range []net.Listener{listeners.outbound, listeners.inbound} {
		port := boundPort(t, captured)
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			ln.Close()
			t.Errorf("capture port %d is not bound by the endpoint", port)
		}
	}

	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the endpoint did not stop after cancellation")
	}
}
