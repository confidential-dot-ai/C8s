package router

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testTick keeps the supervisor's credential re-read short enough for a test.
const testTick = 20 * time.Millisecond

// fakeNginx installs a stub nginx at the path the supervisor runs: -t fails
// while the refuse file exists, and the serving invocation logs every SIGHUP
// until SIGTERM.
func fakeNginx(t *testing.T) (dir string, hups func() int) {
	t.Helper()
	dir = t.TempDir()
	log := filepath.Join(dir, "hup.log")
	refuse := filepath.Join(dir, "refuse")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = -t ]; then [ -e '" + refuse + "' ] && exit 1; exit 0; fi\n" +
		"trap 'echo hup >> \"" + log + "\"' HUP\n" +
		"trap 'exit 0' TERM\n" +
		"while :; do sleep 0.05; done\n"
	if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, func() int {
		content, err := os.ReadFile(log)
		if err != nil {
			return 0
		}
		return strings.Count(string(content), "hup")
	}
}

// credentials writes a watched file set and returns its paths.
func credentials(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	var files []string
	for _, name := range []string{"tls.crt", "tls.key", "ca.crt"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
	}
	return files
}

// superviseWith runs the supervisor against the stub nginx in dir.
func superviseWith(ctx context.Context, t *testing.T, dir string, watched []string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- supervise(ctx, filepath.Join(dir, "nginx"), frontDoor{conf: "/dev/null", credentials: watched}, testTick)
	}()
	return done
}

func TestSuperviseReloadsOnCredentialChange(t *testing.T) {
	dir, hups := fakeNginx(t)
	watched := credentials(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := superviseWith(ctx, t, dir, watched)

	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(watched[0], []byte("renewed"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "nginx was not reloaded after a renewal", func() bool {
		return hups() > 0
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervise: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("supervise did not stop nginx on shutdown")
	}
}

func TestSuperviseExitsOnWithdrawnCredential(t *testing.T) {
	dir, _ := fakeNginx(t)
	watched := credentials(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := superviseWith(ctx, t, dir, watched)

	time.Sleep(50 * time.Millisecond)
	if err := os.Remove(watched[1]); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errWithdrawn) {
			t.Fatalf("supervise returned %v, want a withdrawal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("supervise kept serving a withdrawn generation")
	}
}

// A publication relinks one file at a time, so a file that is back before the
// next read is a renewal, not a withdrawal.
func TestSuperviseSurvivesAFileMissingForOneRead(t *testing.T) {
	dir, hups := fakeNginx(t)
	watched := credentials(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := superviseWith(ctx, t, dir, watched)

	time.Sleep(50 * time.Millisecond)
	content, err := os.ReadFile(watched[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(watched[1]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watched[1], append(content, '!'), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "nginx was not reloaded after the publication landed", func() bool {
		return hups() > 0
	})
	select {
	case err := <-done:
		t.Fatalf("supervise exited on a transient miss: %v", err)
	default:
	}
	cancel()
	<-done
}

func TestSuperviseKeepsRunningConfigurationWhenTheLoadFails(t *testing.T) {
	dir, hups := fakeNginx(t)
	watched := credentials(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := superviseWith(ctx, t, dir, watched)

	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(dir, "refuse"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watched[0], []byte("half-published"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if hups() != 0 {
		t.Fatal("nginx was reloaded onto a configuration it refused")
	}
	if err := os.Remove(filepath.Join(dir, "refuse")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "nginx was not reloaded once the pair was whole", func() bool {
		return hups() > 0
	})
	cancel()
	<-done
}

func TestSuperviseRefusesAConfigurationNginxWillNotLoad(t *testing.T) {
	dir, _ := fakeNginx(t)
	if err := os.WriteFile(filepath.Join(dir, "refuse"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := supervise(context.Background(), filepath.Join(dir, "nginx"), frontDoor{conf: "/dev/null", credentials: credentials(t)}, testTick)
	if err == nil || !strings.Contains(err.Error(), "nginx -t") {
		t.Fatalf("supervise returned %v, want the nginx -t failure", err)
	}
}

func waitFor(t *testing.T, message string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatal(message)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The route data is not a credential: a ConfigMap that goes away, or arrives
// empty, leaves the front door serving the configuration it has, and a file
// the renderer refuses is read again on the next change rather than marked
// seen.
func TestSuperviseKeepsServingThroughBadRouteData(t *testing.T) {
	dir, hups := fakeNginx(t)
	watched := credentials(t)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	routes := writeRoutes(t, validRoutes)
	front := frontDoor{
		cfg:         validConfig(),
		routesFile:  routes,
		conf:        conf,
		credentials: watched,
	}
	if err := front.rerender(context.Background(), filepath.Join(dir, "nginx")); err != nil {
		t.Fatalf("the first render: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- supervise(ctx, filepath.Join(dir, "nginx"), front, testTick)
	}()

	for _, body := range []string{"", `{"routes": [{"path": "/x"}]}`} {
		if err := os.WriteFile(routes, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if hups() != 0 {
			t.Fatalf("nginx was reloaded onto route data the renderer refuses (%q)", body)
		}
	}
	if err := os.Remove(routes); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("the front door exited on withdrawn route data: %v", err)
	default:
	}

	// The same file, corrected, is picked up: the refusals left the last
	// served bytes on record.
	if err := os.WriteFile(routes, []byte(validRoutes), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a corrected routes file was never read again", func() bool {
		return hups() > 0
	})
	cancel()
	<-done
}
