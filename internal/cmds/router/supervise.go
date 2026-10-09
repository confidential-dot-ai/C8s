package router

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// nginxBinary is where the base image installs nginx.
const nginxBinary = "/usr/sbin/nginx"

// errWithdrawn marks a credential C8s took back.
var errWithdrawn = errors.New("the generation was withdrawn")

// fingerprint identifies the bytes of every watched file together.
type fingerprint [sha256.Size]byte

// frontDoor is what the supervisor keeps serving: the credentials nginx
// loads, and the route data it renders its configuration from.
type frontDoor struct {
	cfg Config
	// routesFile is empty on the install lane, where the flags carry the
	// routes and nothing is re-read.
	routesFile  string
	conf        string
	credentials []string
}

// served identifies the bytes the running configuration was rendered and
// loaded from. The two halves are separate because only one of them is a
// credential: a credential that disappears is a withdrawal, route data that
// does is a document to keep ignoring.
type served struct {
	credentials fingerprint
	routes      fingerprint
}

// routesFingerprint identifies the route data as it reads now. A file that is
// gone, empty or unreadable leaves the running configuration in place, like
// one the renderer refuses: the route data is not a credential.
func (f frontDoor) routesFingerprint() (fingerprint, error) {
	if f.routesFile == "" {
		return fingerprint{}, nil
	}
	content, err := os.ReadFile(f.routesFile)
	if err != nil {
		return fingerprint{}, err
	}
	return fingerprint(sha256.Sum256(content)), nil
}

// rerender renders the configuration the current route data describes, tests
// it as nginx will read it, and moves it over the live file only then: a
// refused render leaves the configuration nginx is serving on disk, so a
// restart comes up on it too.
func (f frontDoor) rerender(ctx context.Context, binary string) error {
	if f.routesFile == "" {
		return nil
	}
	cfg, err := readRoutesFile(f.cfg, f.routesFile)
	if err != nil {
		return err
	}
	conf, err := Render(cfg)
	if err != nil {
		return err
	}
	staged := f.conf + ".next"
	if err := os.WriteFile(staged, []byte(conf), 0o600); err != nil {
		return err
	}
	if err := nginxTest(ctx, binary, staged); err != nil {
		return errors.Join(err, os.Remove(staged))
	}
	return os.Rename(staged, f.conf)
}

// supervise runs binary as this process's child and keeps it serving the
// current credentials and route data, re-reading them every tick. It returns
// when nginx exits, when ctx ends, or when a watched credential is withdrawn.
func supervise(ctx context.Context, binary string, front frontDoor, tick time.Duration) error {
	conf := front.conf
	watched := front.credentials
	if err := nginxTest(ctx, binary, conf); err != nil {
		return err
	}
	credentials, err := fileFingerprint(watched)
	if err != nil {
		return err
	}
	routes, err := front.routesFingerprint()
	if err != nil {
		return err
	}
	previous := served{
		credentials: credentials,
		routes:      routes,
	}
	nginx := exec.Command(binary, "-c", conf, "-g", "daemon off;")
	nginx.Stdout = os.Stdout
	nginx.Stderr = os.Stderr
	if err := nginx.Start(); err != nil {
		return err
	}
	// Buffered, and written once by the waiter below.
	exited := make(chan error, 1)
	go func() {
		exited <- nginx.Wait()
	}()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return stopNginx(nginx, exited)
		case err := <-exited:
			return err
		case <-ticker.C:
			credentials, err := fileFingerprint(watched)
			if err != nil {
				if !errors.Is(err, errWithdrawn) {
					return err
				}
				withdrawn := confirmWithdrawal(ctx, watched, tick)
				if withdrawn == nil {
					slog.Warn("a watched file was missing for one read", "error", err)
					continue
				}
				stopped := stopNginx(nginx, exited)
				slog.Error("front door withdrawn", "error", withdrawn, "nginx", stopped)
				return withdrawn
			}
			routes, err := front.routesFingerprint()
			if err != nil {
				slog.Warn("keeping the running configuration: the route data is unreadable", "error", err)
				continue
			}
			current := served{
				credentials: credentials,
				routes:      routes,
			}
			if current == previous {
				continue
			}
			// A refusal leaves the last served bytes on record, so the next
			// tick reads the file again and a corrected one is picked up.
			if err := front.rerender(ctx, binary); err != nil {
				slog.Warn("keeping the running configuration: the route data is refused", "error", err)
				continue
			}
			if err := nginxTest(ctx, binary, conf); err != nil {
				slog.Warn("keeping the running configuration: nginx refuses it", "error", err)
				continue
			}
			if err := signalNginx(nginx, syscall.SIGHUP); err != nil {
				return err
			}
			previous = current
			slog.Info("reloaded nginx", "routes", front.routesFile != "")
		}
	}
}

// fileFingerprint hashes the watched files together. A file that is not there
// is a withdrawal: serving on would present a certificate C8s took back.
func fileFingerprint(watched []string) (fingerprint, error) {
	sum := sha256.New()
	for _, file := range watched {
		content, err := os.ReadFile(file)
		if errors.Is(err, fs.ErrNotExist) {
			return fingerprint{}, fmt.Errorf("%s: %w", file, errWithdrawn)
		}
		if err != nil {
			return fingerprint{}, err
		}
		digest := sha256.Sum256(content)
		sum.Write(digest[:])
	}
	return fingerprint(sum.Sum(nil)), nil
}

// confirmWithdrawal re-reads the watched files one tick later. A publication
// relinks the leaf and its key one file at a time, so a single missing read is
// not yet a withdrawal; a withdrawal is still missing on the next one.
func confirmWithdrawal(ctx context.Context, watched []string, delay time.Duration) error {
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(delay):
	}
	_, err := fileFingerprint(watched)
	if errors.Is(err, errWithdrawn) {
		return err
	}
	return nil
}

func nginxTest(ctx context.Context, binary, conf string) error {
	test := exec.CommandContext(ctx, binary, "-t", "-c", conf)
	out, err := test.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t: %w: %s", err, out)
	}
	return nil
}

func signalNginx(nginx *exec.Cmd, signal syscall.Signal) error {
	if nginx.Process == nil {
		return fmt.Errorf("nginx is not running")
	}
	return nginx.Process.Signal(signal)
}

func stopNginx(nginx *exec.Cmd, exited <-chan error) error {
	if err := signalNginx(nginx, syscall.SIGTERM); err != nil {
		return err
	}
	return <-exited
}
