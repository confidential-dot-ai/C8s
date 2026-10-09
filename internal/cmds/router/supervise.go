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

// supervise runs binary as this process's child and keeps it serving the
// current credentials, re-reading them every tick. It returns when nginx
// exits, when ctx ends, or when a watched file is withdrawn.
func supervise(ctx context.Context, binary, conf string, watched []string, tick time.Duration) error {
	if err := nginxTest(ctx, binary, conf); err != nil {
		return err
	}
	previous, err := fileFingerprint(watched)
	if err != nil {
		return err
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
			current, err := fileFingerprint(watched)
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
			if current == previous {
				continue
			}
			if err := nginxTest(ctx, binary, conf); err != nil {
				slog.Warn("keeping the running configuration", "error", err)
				continue
			}
			if err := signalNginx(nginx, syscall.SIGHUP); err != nil {
				return err
			}
			previous = current
			slog.Info("reloaded nginx on a credential change")
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
