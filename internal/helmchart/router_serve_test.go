package helmchart

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// routerConfigDir is where the chart mounts the router's nginx configuration,
// serve.sh included (the chart's router.configDir).
const routerConfigDir = "/mnt/c8s-data/nginx"

// nginx is its entrypoint's child, so the credential watch needs no shared
// process namespace, which would expose the credential containers' /proc to
// nginx.
func TestChartRouterServesWithoutASharedProcessNamespace(t *testing.T) {
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
	if want := []string{"/bin/sh", routerConfigDir + "/serve.sh"}; !slices.Equal(nginx.Command, want) {
		t.Errorf("nginx command = %v, want the shell that runs the entrypoint %v", nginx.Command, want)
	}
	if len(nginx.Args) != 0 {
		t.Errorf("nginx args = %v, want none: its measured entry denies them", nginx.Args)
	}
	var mounts []corev1.VolumeMount
	for _, m := range nginx.VolumeMounts {
		if m.MountPath == routerConfigDir {
			mounts = append(mounts, m)
		}
	}
	if len(mounts) != 1 {
		t.Fatalf("nginx mounts %d entries at %s, want exactly one: %+v", len(mounts), routerConfigDir, nginx.VolumeMounts)
	}
	if !mounts[0].ReadOnly {
		t.Errorf("nginx config mount = %+v, want read-only", mounts[0])
	}

	// Nothing signals nginx: a signaller would need the shared namespace.
	for _, c := range append(spec.Containers, spec.InitContainers...) {
		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "--reload-nginx") {
				t.Errorf("%s carries %q; nothing reloads nginx", c.Name, arg)
			}
		}
	}
}

// The entrypoint watches the credentials the router serves: the ones get-cert
// publishes, and the public certificate of whichever TLS mode is on.
func TestChartRouterServeWatchesTheServedCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		line string
	}{
		{
			name: "mesh leaf",
			line: `watched="/etc/c8s/certs/tls.crt /etc/c8s/certs/tls.key /etc/c8s/certs/ca.crt"`,
		},
		{
			name: "public web PKI certificate",
			args: []string{"--set-string", "router.publicTLS.mode=webpki", "--set-string", "router.publicTLS.secretName=front-door"},
			line: `watched="/etc/c8s/certs/tls.crt /etc/c8s/certs/tls.key /etc/c8s/certs/ca.crt /mnt/c8s-data/public-tls/tls.crt /mnt/c8s-data/public-tls/tls.key"`,
		},
		{
			name: "acme certificate and key",
			args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "router.san={lb.example.com}", "--set-string", "router.acme.email=ops@example.com"},
			line: `watched="/etc/c8s/certs/tls.crt /etc/c8s/certs/tls.key /etc/c8s/certs/ca.crt /etc/c8s-acme-tls/cert.pem /etc/c8s-acme-key/key.pem"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			script := renderedConfigMap(t, out, "c8s-router-nginx").Data["serve.sh"]
			if !strings.Contains(script, tc.line) {
				t.Errorf("serve.sh does not carry the line %s:\n%s", tc.line, script)
			}
		})
	}
}

// Every certificate and key nginx serves names the always-empty
// $per_handshake, so nginx reads them on each TLS handshake and a renewal
// needs no reload, which would close every idle connection.
func TestChartRouterReadsItsCertificatePerHandshake(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "cds"},
		{name: "webpki", args: []string{"--set-string", "router.publicTLS.mode=webpki", "--set-string", "router.publicTLS.secretName=front-door"}},
		{name: "acme", args: []string{"--set-string", "router.publicTLS.mode=acme", "--set", "router.san={lb.example.com}", "--set-string", "router.acme.email=ops@example.com"}},
		{name: "baked", args: bakedArgs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			data := renderedConfigMap(t, out, "c8s-router-nginx").Data
			cfg := parseNginxConfig(t, data["nginx.conf"])
			perHandshake, ok := cfg.maps[nginxMapKey{source: "$ssl_server_name", target: "$per_handshake"}]
			if !ok {
				t.Fatal("nginx.conf defines no $per_handshake map")
			}
			perHandshake.assertDirective(t, "default", `""`)

			var served []string
			for _, conf := range []string{data["nginx.conf"], data["tls-cds.conf"], data["tls-acme.conf"]} {
				for _, block := range parseNginxConfig(t, "server {\n"+conf+"\n}").all {
					for _, name := range []string{"ssl_certificate", "ssl_certificate_key"} {
						for _, args := range block.directives[name] {
							served = append(served, args...)
						}
					}
				}
			}
			if len(served) == 0 {
				t.Fatal("nginx serves no certificate")
			}
			for _, path := range served {
				if !strings.HasSuffix(path, "$per_handshake") {
					t.Errorf("nginx loads %s once, at start; want it read per handshake", path)
				}
			}
		})
	}
}

// A renewal replaces the certificate and key nginx serves; the entrypoint
// signals nothing and nginx keeps running, so no connection is closed.
func TestRouterServeLeavesNginxRunningThroughARenewal(t *testing.T) {
	run := startServeScript(t, nil, func(tlsDir string) {
		for _, name := range []string{"tls.key", "tls.crt", "ca.crt"} {
			writeAtomic(t, filepath.Join(tlsDir, name), "pair-1")
		}
	})

	writeAtomic(t, filepath.Join(run.tlsDir, "tls.key"), "pair-2")
	writeAtomic(t, filepath.Join(run.tlsDir, "tls.crt"), "pair-2")
	run.waitTicks(t, 5)

	if run.exited() {
		t.Fatalf("the entrypoint exited on a renewal:\n%s", scriptLog(t, run.log))
	}
	if signals, _ := os.ReadFile(run.signals); len(signals) > 0 {
		t.Fatalf("nginx was signalled on a renewal: %q", signals)
	}
}

func TestRouterServeRecoversAfterCredentialWithdrawal(t *testing.T) {
	run := startServeScript(t, nil, func(tlsDir string) {
		for _, name := range []string{"tls.key", "tls.crt", "ca.crt"} {
			writeAtomic(t, filepath.Join(tlsDir, name), "pair-1")
		}
	})

	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		run.withdrawAndRestore(t, filepath.Join(run.tlsDir, name))
	}
}

// A baked node takes its front-door mode from the launch file at runtime, so
// the entrypoint adds the ACME certificate and key to the watch when that mode
// is acme.
func TestChartBakedRouterServeWatchesTheACMECertificate(t *testing.T) {
	out, err := helmTemplate(t, bakedArgs...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	script := renderedConfigMap(t, out, "c8s-router-nginx").Data["serve.sh"]
	for _, line := range []string{
		`if [ "$(cat /run/c8s-node/router/front-door-mode)" = acme ]; then`,
		`watched="$watched /etc/c8s-acme-tls/cert.pem /etc/c8s-acme-key/key.pem"`,
	} {
		if !strings.Contains(script, line) {
			t.Errorf("baked serve.sh does not carry the line %s:\n%s", line, script)
		}
	}
}

// Running the baked script in both front-door modes: each stops nginx when
// a credential it serves is withdrawn, the mesh leaf in either mode and the
// ACME certificate in acme mode. In cds mode the standby acme sidecar writes no
// ACME files, and their absence is no withdrawal.
func TestBakedRouterServeFollowsTheFrontDoorMode(t *testing.T) {
	for _, tc := range []struct {
		mode, withdraw string
	}{
		{mode: "acme", withdraw: "acme/cert.pem"},
		{mode: "acme", withdraw: "acme/key.pem"},
		{mode: "acme", withdraw: "mesh/tls.crt"},
		{mode: "cds", withdraw: "mesh/tls.crt"},
	} {
		t.Run(tc.mode+" "+tc.withdraw, func(t *testing.T) {
			run := startServeScript(t, bakedArgs, func(dir string) {
				for _, d := range []string{"mesh", "acme", "launch"} {
					if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				writeAtomic(t, filepath.Join(dir, "launch", "front-door-mode"), tc.mode)
				for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
					writeAtomic(t, filepath.Join(dir, "mesh", name), "mesh-1")
				}
				if tc.mode == "acme" {
					writeAtomic(t, filepath.Join(dir, "acme", "cert.pem"), "issued")
					writeAtomic(t, filepath.Join(dir, "acme", "key.pem"), "issued")
				}
			})
			run.waitTicks(t, 5)
			if run.exited() {
				t.Fatalf("the entrypoint stopped nginx before any withdrawal:\n%s", scriptLog(t, run.log))
			}
			run.withdrawAndRestore(t, filepath.Join(run.tlsDir, tc.withdraw))
		})
	}
}

func TestRouterServeWaitsForInitialCredentials(t *testing.T) {
	run := launchServeScript(t, nil, func(string) {})
	writeAtomic(t, filepath.Join(run.tlsDir, "tls.crt"), "pair-1")
	writeAtomic(t, filepath.Join(run.tlsDir, "tls.key"), "pair-1")
	run.waitTicks(t, 3)
	if tickCount(run.starts) != 0 {
		t.Fatal("nginx started without the CA bundle")
	}
	writeAtomic(t, filepath.Join(run.tlsDir, "ca.crt"), "pair-1")
	run.waitStarts(t, 1)
}

func TestRouterServeShutdown(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT} {
		for _, serving := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/serving=%t", sig, serving), func(t *testing.T) {
				run := launchServeScript(t, nil, func(dir string) {
					if serving {
						writeAtomic(t, filepath.Join(dir, "tls.crt"), "pair-1")
						writeAtomic(t, filepath.Join(dir, "tls.key"), "pair-1")
						writeAtomic(t, filepath.Join(dir, "ca.crt"), "pair-1")
					}
				})
				if serving {
					run.waitStarts(t, 1)
				} else {
					run.waitTicks(t, 2)
				}
				if err := run.process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				if err := run.wait(t); err != nil {
					t.Fatalf("shutdown: %v\n%s", err, scriptLog(t, run.log))
				}
				if serving {
					assertProcessReaped(t, run.nginxPID(t))
					want := syscall.SIGTERM
					if sig == syscall.SIGQUIT {
						want = syscall.SIGQUIT
					}
					if got := scriptLog(t, run.signals); got != want.String() {
						t.Fatalf("nginx received %q, want %s", got, want)
					}
				}
			})
		}
	}
}

func TestRouterServePropagatesUnexpectedNginxExit(t *testing.T) {
	run := startServeScript(t, nil, func(dir string) {
		writeAtomic(t, filepath.Join(dir, "tls.crt"), "pair-1")
		writeAtomic(t, filepath.Join(dir, "tls.key"), "pair-1")
		writeAtomic(t, filepath.Join(dir, "ca.crt"), "pair-1")
	})
	if err := syscall.Kill(run.nginxPID(t), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := run.wait(t); !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("nginx exit 42 became %v", err)
	}
	if got := tickCount(run.starts); got != 1 {
		t.Fatalf("nginx started %d times after unexpected failure", got)
	}
}

// Each start names itself: the entrypoint writes a fresh $nginx_start, which
// nginx.conf includes and the connection identifier carries, so identifiers
// from before an nginx restart are never reused.
func TestRouterServeNamesEachStart(t *testing.T) {
	var starts []string
	for range 2 {
		run := startServeScript(t, nil, func(tlsDir string) {
			for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
				writeAtomic(t, filepath.Join(tlsDir, name), "pair-1")
			}
		})
		conf, err := os.ReadFile(run.startConf)
		if err != nil {
			t.Fatal(err)
		}
		start := regexp.MustCompile(`(?s)^map \$pid \$nginx_start \{\n    default "([0-9a-f]{16})";\n\}\n$`).FindSubmatch(conf)
		if start == nil {
			t.Fatalf("the start file = %q, want a map of $nginx_start to 16 hex digits", conf)
		}
		starts = append(starts, string(start[1]))
	}
	if starts[0] == starts[1] {
		t.Fatalf("two starts both named themselves %s", starts[0])
	}

	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	cfg := renderedRouterNginxConfig(t, out)
	cfg.http.assertDirective(t, "include", "/tmp/nginx-start.conf")
}

// The front door resumes no TLS session: a resumed session keeps the leaf it
// began with after a renewal, while attest-lb attests the leaf on disk.
func TestChartRouterResumesNoTLSSession(t *testing.T) {
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	server := renderedRouterNginxConfig(t, out).server(t)
	server.assertDirective(t, "ssl_session_cache", "off")
	server.assertDirective(t, "ssl_session_tickets", "off")
	server.assertNoDirective(t, "ssl_session_timeout")
}

// serveRun is the shipped serve.sh running against fixture credentials and a
// stub nginx.
type serveRun struct {
	tlsDir    string // the fixture tree the script's paths point into
	startConf string // where the script writes $nginx_start
	signals   string // the latest child's terminating signal
	ticks     string // one line per sleep the script took
	log       string
	done      chan error
	starts    string
	process   *os.Process
}

// startServeScript runs the rendered script against fixture credentials until nginx starts.
func startServeScript(
	t *testing.T,
	args []string,
	stage func(dir string),
) *serveRun {
	t.Helper()
	run := launchServeScript(t, args, stage)
	run.waitStarts(t, 1)
	return run
}

func launchServeScript(
	t *testing.T,
	args []string,
	stage func(dir string),
) *serveRun {
	t.Helper()
	dir := t.TempDir()
	run := &serveRun{
		tlsDir:    filepath.Join(dir, "tls"),
		startConf: filepath.Join(dir, "nginx-start.conf"),
		signals:   filepath.Join(dir, "signals"),
		ticks:     filepath.Join(dir, "ticks"),
		log:       filepath.Join(dir, "serve.log"),
		done:      make(chan error, 1),
		starts:    filepath.Join(dir, "starts"),
	}
	if err := os.MkdirAll(run.tlsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stage(run.tlsDir)

	out, err := helmTemplate(t, args...)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	paths := []string{"/tmp/nginx-start.conf", run.startConf, "/etc/c8s/certs/", run.tlsDir + "/"}
	if args != nil {
		paths = []string{
			"/tmp/nginx-start.conf", run.startConf,
			"/etc/c8s/certs/", run.tlsDir + "/mesh/",
			"/etc/c8s-acme-tls/", run.tlsDir + "/acme/",
			"/etc/c8s-acme-key/", run.tlsDir + "/acme/",
			"/run/c8s-node/router/", run.tlsDir + "/launch/",
		}
	}
	body := strings.NewReplacer(paths...).Replace(renderedConfigMap(t, out, "c8s-router-nginx").Data["serve.sh"])
	script := filepath.Join(dir, "serve.sh")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	stubNginx(t, dir, run.ticks)
	logFile, err := os.Create(run.log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logFile.Close() })
	cmd := exec.Command("/bin/sh", script)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+":"+os.Getenv("PATH"))
	cmd.Env = append(cmd.Env, "C8S_TEST_NGINX_STARTS="+run.starts, "C8S_TEST_NGINX_SIGNALS="+run.signals)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	run.process = cmd.Process
	go func() { run.done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	return run
}

func (r *serveRun) waitStarts(
	t *testing.T,
	count int,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !r.exited() {
		if tickCount(r.starts) >= count {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nginx did not start %d times:\n%s", count, scriptLog(t, r.log))
}

func (r *serveRun) nginxPID(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(r.starts)
	if err != nil {
		t.Fatal(err)
	}
	pids := strings.Fields(string(data))
	pid, err := strconv.Atoi(pids[len(pids)-1])
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func assertProcessReaped(
	t *testing.T,
	pid int,
) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("nginx %d still exists: %v", pid, err)
	}
}

func (r *serveRun) withdrawAndRestore(
	t *testing.T,
	path string,
) {
	t.Helper()
	pid := r.nginxPID(t)
	starts := tickCount(r.starts)
	startID := scriptLog(t, r.startConf)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.waitTicks(t, 5)
	assertProcessReaped(t, pid)
	if got := tickCount(r.starts); got != starts {
		t.Fatalf("nginx restarted with a missing credential: starts %d, want %d", got, starts)
	}
	writeAtomic(t, path, "pair-2")
	r.waitStarts(t, starts+1)
	if scriptLog(t, r.startConf) == startID {
		t.Fatal("nginx reused its connection identifier after recovery")
	}
}

// waitTicks waits until the script has slept n more times, so each of its
// checks has seen the fixture as it now stands.
func (r *serveRun) waitTicks(
	t *testing.T,
	n int,
) {
	t.Helper()
	start := tickCount(r.ticks)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !r.exited() {
		if tickCount(r.ticks) >= start+n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("entrypoint stopped polling credentials:\n%s", scriptLog(t, r.log))
}

func tickCount(path string) int {
	data, _ := os.ReadFile(path)
	return strings.Count(string(data), "\n")
}

// exited reports whether the script has exited, keeping its result for wait.
func (r *serveRun) exited() bool {
	select {
	case err := <-r.done:
		r.done <- err
		return true
	default:
		return false
	}
}

// wait returns the script's exit error once it exits.
func (r *serveRun) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(20 * time.Second):
		t.Fatalf("the entrypoint is still running:\n%s", scriptLog(t, r.log))
		return nil
	}
}

// writeAtomic replaces a file by rename, the way a publication relinks one.
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

// The child process records starts and signals; SIGUSR1 simulates a fatal exit.
func TestRouterNginxProcess(t *testing.T) {
	starts := os.Getenv("C8S_TEST_NGINX_STARTS")
	if starts == "" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGUSR1)
	f, err := os.OpenFile(starts, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(f, os.Getpid()); err != nil {
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		os.Exit(1)
	}
	sig := <-signals
	if sig == syscall.SIGUSR1 {
		os.Exit(42)
	}
	if err := os.WriteFile(os.Getenv("C8S_TEST_NGINX_SIGNALS"), []byte(sig.String()), 0o600); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// Stub nginx uses this test binary; sleep advances the polling loop quickly.
func stubNginx(
	t *testing.T,
	dir string,
	ticks string,
) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	nginx := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=^TestRouterNginxProcess$\n", exe)
	if err := os.WriteFile(filepath.Join(bin, "nginx"), []byte(nginx), 0o755); err != nil {
		t.Fatal(err)
	}
	sleep := "#!/bin/sh\necho tick >> " + ticks + "\nexec /bin/sleep 0.05\n"
	if err := os.WriteFile(filepath.Join(bin, "sleep"), []byte(sleep), 0o755); err != nil {
		t.Fatal(err)
	}
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
