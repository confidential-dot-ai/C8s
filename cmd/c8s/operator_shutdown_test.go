//go:build !c8s_node

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const operatorHelperKubeconfigEnv = "C8S_OPERATOR_HELPER_KUBECONFIG"

// SIGTERM reaches the operator as a cancelled context: its manager stops and
// the process exits 0 rather than dying on the signal.
func TestOperatorStopsItsManagerOnSIGTERM(t *testing.T) {
	leaseRequested := make(chan struct{})
	var once sync.Once
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if discovery, ok := operatorDiscovery[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, discovery)
			return
		}
		if strings.Contains(r.URL.Path, "/leases/") {
			once.Do(func() { close(leaseRequested) })
		}
		<-r.Context().Done()
	}))
	defer api.Close()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	operator := exec.CommandContext(ctx, executable, "-test.run=^TestOperatorHelper$")
	operator.Env = append(os.Environ(), operatorHelperKubeconfigEnv+"="+writeKubeconfig(t, api.URL))
	operator.Stderr = os.Stderr
	if err := operator.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-leaseRequested:
	case <-ctx.Done():
		t.Fatal("the operator never asked for its leader-election lease")
	}
	if err := operator.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := operator.Wait(); err != nil {
		t.Fatalf("operator ended with %v after SIGTERM, want exit status 0", err)
	}
}

// operatorDiscovery is the API discovery the operator's manager needs before
// it starts.
var operatorDiscovery = map[string]string{
	"/api":    `{"kind":"APIVersions","versions":["v1"]}`,
	"/apis":   `{"kind":"APIGroupList","apiVersion":"v1","groups":[]}`,
	"/api/v1": `{"kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"services","singularName":"service","namespaced":true,"kind":"Service","verbs":["get","list","watch"]}]}`,
}

// TestOperatorHelper is the c8s process the test above signals.
func TestOperatorHelper(t *testing.T) {
	kubeconfig := os.Getenv(operatorHelperKubeconfigEnv)
	if kubeconfig == "" {
		return
	}
	os.Args = []string{
		"c8s",
		"operator",
		"--kubeconfig=" + kubeconfig,
		"--status-mirror-enabled=false",
		"--metrics-bind-address=0",
		"--health-probe-bind-address=0",
	}
	main()
}

// writeKubeconfig points a kubeconfig at server.
func writeKubeconfig(t *testing.T, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: %s
users:
- name: test
  user:
    token: test
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
`, server)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
