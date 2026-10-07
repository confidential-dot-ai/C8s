package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// The router reloads itself from inside the nginx container: nginx is the
// entrypoint's child, so the credential watch needs no shared process
// namespace, which would expose the credential containers' /proc to nginx.
func TestChartRouterReloadsWithoutASharedProcessNamespace(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	router := renderedDeployment(t, out, "c8s-router")
	spec := router.Spec.Template.Spec

	if spec.ShareProcessNamespace != nil {
		t.Errorf("the router pod sets shareProcessNamespace=%v; nginx must not see the credential containers' /proc", *spec.ShareProcessNamespace)
	}
	nginx, ok := findContainer(spec.Containers, "nginx")
	if !ok {
		t.Fatalf("no nginx container; got %v", containerNames(spec.Containers))
	}
	if want := []string{"/bin/sh", "/etc/nginx/reload.sh"}; !slices.Equal(nginx.Command, want) {
		t.Errorf("nginx command = %v, want the reloading entrypoint %v", nginx.Command, want)
	}
	var mounts []corev1.VolumeMount
	for _, m := range nginx.VolumeMounts {
		if m.MountPath == "/etc/nginx/reload.sh" {
			mounts = append(mounts, m)
		}
	}
	if len(mounts) != 1 {
		t.Fatalf("nginx mounts %d entries at /etc/nginx/reload.sh, want exactly one: %+v", len(mounts), nginx.VolumeMounts)
	}
	if mounts[0].SubPath != "reload.sh" || !mounts[0].ReadOnly {
		t.Errorf("reload.sh mount = %+v, want subPath reload.sh, read-only", mounts[0])
	}

	// The entrypoint is the only signaller: a second one would need the
	// shared namespace.
	for _, c := range append(spec.Containers, spec.InitContainers...) {
		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "--reload-nginx") && arg != "--reload-nginx=false" {
				t.Errorf("%s carries %q; one owner reloads nginx", c.Name, arg)
			}
		}
	}
}

// The entrypoint watches the files nginx serves: the credentials get-cert
// publishes, and the public certificate of whichever TLS mode is on.
func TestChartRouterReloadWatchesTheServedCertificates(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		line string
	}{
		{
			name: "mesh leaf",
			line: `watched="/tls/cert.pem /tls/key.pem /tls/ca.pem"`,
		},
		{
			name: "public web PKI certificate",
			args: []string{"--set-string", "router.publicTLS.mode=webpki", "--set-string", "router.publicTLS.secretName=front-door"},
			line: `watched="/tls/cert.pem /tls/key.pem /tls/ca.pem /public-tls/tls.crt /public-tls/tls.key"`,
		},
		{
			name: "acme certificate and key",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "router.san={lb.example.com}", "--set-string", "router.acme.email=ops@example.com"},
			line: `watched="/tls/cert.pem /tls/key.pem /tls/ca.pem /etc/c8s-acme-tls/cert.pem /etc/c8s-acme-tls/key.pem"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			script := renderedConfigMap(t, out, "c8s-router-nginx").Data["reload.sh"]
			if !strings.Contains(script, tc.line) {
				t.Errorf("reload.sh does not carry the line %s:\n%s", tc.line, script)
			}
		})
	}
}

// A publication relinks the leaf and its key one file at a time, so the watcher
// can see a changed leaf before its key arrives. Running the shipped script
// against a stub nginx that refuses a mismatched pair: every reload it signals
// carries a pair nginx accepted.
func TestRouterReloadSignalsOnlyAPairNginxAccepts(t *testing.T) {
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePair(t, tlsDir, "pair-1", "pair-1")

	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	script := filepath.Join(dir, "reload.sh")
	body := watchFixtureTree(t, renderedConfigMap(t, out, "c8s-router-nginx").Data["reload.sh"], tlsDir)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	ready := filepath.Join(dir, "ready")
	reloads := filepath.Join(dir, "reloads")
	stubNginx(t, dir, tlsDir, ready, reloads)

	// The script's own output goes to a file: the test reads it while the
	// script still runs.
	logPath := filepath.Join(dir, "reload.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd := exec.Command("/bin/sh", script)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"))
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})
	waitForFile(t, ready, "the entrypoint never started nginx", logPath)

	// The window a publication leaves open: the new leaf is linked, its key is
	// not yet.
	writeAtomic(t, filepath.Join(tlsDir, "cert.pem"), "pair-2")
	time.Sleep(500 * time.Millisecond)
	writeAtomic(t, filepath.Join(tlsDir, "key.pem"), "pair-2")

	waitForFile(t, reloads, "nginx was never reloaded after the publication", logPath)
	time.Sleep(500 * time.Millisecond)
	signalled, err := os.ReadFile(reloads)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Fields(strings.TrimSpace(string(signalled))) {
		if line != "pair-2:pair-2" {
			t.Fatalf("a reload carried %q; nginx only ever loads a matching pair:\n%s", line, scriptLog(t, logPath))
		}
	}
	if !strings.Contains(scriptLog(t, logPath), "nginx will not load the watched files") {
		t.Errorf("the watcher never waited on the half-published pair:\n%s", scriptLog(t, logPath))
	}
}

// watchFixtureTree points the shipped script at the fixture's three files; the
// paths it ships with are covered by the template test above.
func watchFixtureTree(t *testing.T, script, dir string) string {
	t.Helper()
	line := regexp.MustCompile(`(?m)^(\s*)watched=".*"$`)
	if !line.MatchString(script) {
		t.Fatalf("reload.sh carries no watched file list:\n%s", script)
	}
	files := []string{filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem")}
	return line.ReplaceAllString(script, `${1}watched="`+strings.Join(files, " ")+`"`)
}

// writePair stages the three files nginx loads; cert and key carry the pair
// they belong to.
func writePair(t *testing.T, dir, cert, key string) {
	t.Helper()
	writeAtomic(t, filepath.Join(dir, "cert.pem"), cert)
	writeAtomic(t, filepath.Join(dir, "key.pem"), key)
	writeAtomic(t, filepath.Join(dir, "ca.pem"), "ca")
}

// writeAtomic replaces a watched file by rename, the way a publication relinks
// one.
func writeAtomic(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// stubNginx puts an nginx and a sleep on PATH: nginx -t stands for nginx
// loading what it would serve and fails on a cert and key from different
// pairs, the serving mode records the pair every reload signal carries, and
// sleep collapses the script's waits so the test does not run on its cadence.
func stubNginx(t *testing.T, dir, tlsDir, ready, reloads string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(tlsDir, "cert.pem")
	key := filepath.Join(tlsDir, "key.pem")
	nginx := `#!/bin/sh
pair() { printf '%s:%s' "$(cat ` + cert + `)" "$(cat ` + key + `)" | tr -d '\n'; }
if [ "$1" = "-t" ]; then
    [ "$(cat ` + cert + `)" = "$(cat ` + key + `)" ] || exit 1
    exit 0
fi
trap 'pair >> ` + reloads + `; printf "\n" >> ` + reloads + `' HUP
echo ready > ` + ready + `
while :; do /bin/sleep 0.05; done
`
	if err := os.WriteFile(filepath.Join(bin, "nginx"), []byte(nginx), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "sleep"), []byte("#!/bin/sh\nexec /bin/sleep 0.05\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// waitForFile waits for the stub to report what the script did, and prints the
// script's own output when it does not.
func waitForFile(t *testing.T, path, msg, logPath string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s:\n%s", msg, scriptLog(t, logPath))
}

// scriptLog is what the running script has said so far.
func scriptLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
