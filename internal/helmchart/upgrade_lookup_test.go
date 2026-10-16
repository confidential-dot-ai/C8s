package helmchart

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeCluster is the API server a helm render with --dry-run=server looks
// up: discovery, kube-system when present, and the CDS Deployment when
// deployment is not empty. It records the objects the render read.
type fakeCluster struct {
	kubeSystem bool
	deployment string // the c8s-cds Deployment as JSON, "" for none

	mu    sync.Mutex
	reads []string
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	found := func(body string) {
		f.mu.Lock()
		f.reads = append(f.reads, r.URL.Path)
		f.mu.Unlock()
		if body == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
			return
		}
		fmt.Fprint(w, body)
	}
	switch r.URL.Path {
	case "/version":
		fmt.Fprint(w, `{"major":"1","minor":"30","gitVersion":"v1.30.0"}`)
	case "/api":
		fmt.Fprint(w, `{"kind":"APIVersions","versions":["v1"]}`)
	case "/apis":
		fmt.Fprint(w, `{"kind":"APIGroupList","groups":[{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}}]}`)
	case "/api/v1":
		fmt.Fprint(w, `{"kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"namespaces","namespaced":false,"kind":"Namespace","verbs":["get"]},{"name":"secrets","namespaced":true,"kind":"Secret","verbs":["list"]}]}`)
	case "/apis/apps/v1":
		fmt.Fprint(w, `{"kind":"APIResourceList","groupVersion":"apps/v1","resources":[{"name":"deployments","namespaced":true,"kind":"Deployment","verbs":["get"]}]}`)
	case "/api/v1/namespaces/kube-system":
		body := ""
		if f.kubeSystem {
			body = `{"kind":"Namespace","apiVersion":"v1","metadata":{"name":"kube-system"}}`
		}
		found(body)
	case "/apis/apps/v1/namespaces/c8s-system/deployments/c8s-cds":
		found(f.deployment)
	case "/api/v1/namespaces/c8s-system/secrets":
		fmt.Fprint(w, `{"kind":"SecretList","apiVersion":"v1","items":[]}`)
	default:
		found("")
	}
}

// The guard reads the running CDS from the cluster: the Deployment first,
// kube-system only to tell a first install apart, and nothing once the
// rendered shape is published.
func TestCDSShapeGuardLookups(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	tpl, err := os.ReadFile("c8s/templates/_upgrade.tpl")
	if err != nil {
		t.Fatal(err)
	}
	chart := t.TempDir()
	for name, body := range map[string]string{
		"Chart.yaml":             "apiVersion: v2\nname: guard\nversion: 0.0.1\n",
		"values.yaml":            "node:\n  baked: false\ncds:\n  publishedShape: \"\"\n  liveShape: \"\"\n",
		"templates/_upgrade.tpl": string(tpl),
		"templates/guard.yaml":   `{{- define "c8s.cdsName" -}}c8s-cds{{- end -}}` + "\n" + `{{ include "c8s.cdsShapeCheck" (dict "root" . "want" "cds-new") }}`,
	} {
		path := filepath.Join(chart, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	deployment := func(annotations string) string {
		return `{"kind":"Deployment","apiVersion":"apps/v1","metadata":{"name":"c8s-cds","namespace":"c8s-system","annotations":{` + annotations + `}}}`
	}
	const (
		readsDeployment = "/apis/apps/v1/namespaces/c8s-system/deployments/c8s-cds"
		readsKubeSystem = "/api/v1/namespaces/kube-system"
	)
	for _, tc := range []struct {
		name      string
		cluster   *fakeCluster
		args      []string
		fails     bool
		wantReads []string
	}{
		{name: "first install", cluster: &fakeCluster{kubeSystem: true}, wantReads: []string{readsDeployment, readsKubeSystem}},
		{name: "running the rendered shape", cluster: &fakeCluster{kubeSystem: true, deployment: deployment(`"confidential.ai/cds-shape":"cds-new"`)}, wantReads: []string{readsDeployment}},
		{name: "running another shape", cluster: &fakeCluster{kubeSystem: true, deployment: deployment(`"confidential.ai/cds-shape":"cds-old"`)}, fails: true, wantReads: []string{readsDeployment}},
		{name: "published", cluster: &fakeCluster{kubeSystem: true, deployment: deployment(`"confidential.ai/cds-shape":"cds-old"`)}, args: []string{"--set", "cds.publishedShape=cds-new"}},
		{name: "unannotated", cluster: &fakeCluster{kubeSystem: true, deployment: deployment("")}, fails: true, wantReads: []string{readsDeployment}},
		{name: "unannotated claimed absent", cluster: &fakeCluster{kubeSystem: true, deployment: deployment("")}, args: []string{"--set", "cds.liveShape=none"}, fails: true, wantReads: []string{readsDeployment}},
		{name: "unannotated stated", cluster: &fakeCluster{kubeSystem: true, deployment: deployment("")}, args: []string{"--set", "cds.liveShape=cds-new"}, wantReads: []string{readsDeployment}},
		{name: "kube-system unreadable", cluster: &fakeCluster{}, fails: true, wantReads: []string{readsDeployment, readsKubeSystem}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.cluster)
			defer srv.Close()
			kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
			config := "apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: " + srv.URL + "}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\nusers: [{name: u, user: {}}]\ncurrent-context: c\n"
			if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("helm", append([]string{"template", "g", chart, "--dry-run=server", "--kubeconfig", kubeconfig, "-n", "c8s-system"}, tc.args...)...).CombinedOutput()
			if (err != nil) != tc.fails {
				t.Fatalf("render error = %v, want failure %t\n%s", err, tc.fails, out)
			}
			if tc.fails && !strings.Contains(string(out), "cds.publishedShape=cds-new") {
				t.Errorf("failure does not name the entry to publish:\n%s", out)
			}
			tc.cluster.mu.Lock()
			defer tc.cluster.mu.Unlock()
			if !slices.Equal(tc.cluster.reads, tc.wantReads) {
				t.Errorf("render read %q, want %q", tc.cluster.reads, tc.wantReads)
			}
		})
	}
}
