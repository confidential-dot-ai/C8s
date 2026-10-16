package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// The advertise host is what CDS dials back. Getting it wrong took the plugin
// down on a stock install once already: route inference against the chart's
// default CDS URL (the NodePort on loopback) yields loopback, which is not a
// routable address. These pin each source and that regression.
func TestDigestsAdvertiseHost(t *testing.T) {
	const loopbackCDS = "https://127.0.0.1:30808"

	t.Run("explicit config wins", func(t *testing.T) {
		cfg := &config{}
		cfg.WorkloadClaims.AdvertiseHost = "10.1.2.3"
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.1.2.3" {
			t.Fatalf("host = %q, err = %v; want 10.1.2.3", got, err)
		}
	})

	t.Run("installer node-ip file is used when config is empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, NodeIPFile), []byte("10.4.5.6\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = dir
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.4.5.6" {
			t.Fatalf("host = %q, err = %v; want 10.4.5.6", got, err)
		}
	})

	t.Run("environment is the last source, for the baked node image", func(t *testing.T) {
		t.Setenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST", "10.7.8.9")
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = t.TempDir() // no node-ip file
		cfg.Allowlist.Pull.URL = loopbackCDS
		got, err := digestsAdvertiseHost(cfg)
		if err != nil || got != "10.7.8.9" {
			t.Fatalf("host = %q, err = %v; want 10.7.8.9", got, err)
		}
	})

	// The regression: with no source at all, inference runs against a loopback
	// CDS URL and yields loopback, which must be rejected rather than
	// advertised. It fails here, at startup, not as an unreachable callback.
	t.Run("loopback CDS URL alone is rejected", func(t *testing.T) {
		cfg := &config{}
		cfg.WorkloadClaims.SocketDir = t.TempDir()
		cfg.Allowlist.Pull.URL = loopbackCDS
		if got, err := digestsAdvertiseHost(cfg); err == nil {
			t.Fatalf("host = %q, want an error: loopback is not an address CDS can dial back", got)
		}
	})
}

// Components trust node-ip as their verifier address, so it comes from the
// host's own view, never from a pod. They bind-mount the file itself, so every
// update must reach the inode a running pod already holds, which the hard link
// stands in for. The file starts with a stale address, so a resolved one is
// published at the second recheck, and a failure leaves the stale one.
func TestPublishNodeIP(t *testing.T) {
	const stale = "203.0.113.66\n"
	for _, tc := range []struct {
		name          string
		advertiseHost string
		kubeletArgs   []string
		podArgs       []string
		hostIP        net.IP
		hostErr       error
		writeErr      error
		want          string
		wantErr       bool
	}{
		{name: "host interface", hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "advertise host IP wins", advertiseHost: "192.0.2.20", kubeletArgs: []string{"--node-ip=192.0.2.30"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.20\n"},
		{name: "advertise hostname is not an address", advertiseHost: "node-a.example", hostIP: net.ParseIP("2001:db8::1"), want: "2001:db8::1\n"},
		{name: "kubelet node-ip wins over the default route", kubeletArgs: []string{"--v=2", "--node-ip=192.0.2.30,2001:db8::30"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.30\n"},
		{name: "kubelet node-ip as a separate argument", kubeletArgs: []string{"--node-ip", "192.0.2.31"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.31\n"},
		{name: "kubelet without node-ip falls back to the default route", kubeletArgs: []string{"--v=2"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "unspecified kubelet node-ip falls back to the default route", kubeletArgs: []string{"--node-ip=::"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "unspecified IPv4 kubelet node-ip falls back to the default route", kubeletArgs: []string{"--node-ip=0.0.0.0"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "loopback kubelet node-ip falls back to the default route", kubeletArgs: []string{"--node-ip=127.0.0.1"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "unspecified advertise host empties a stale file", advertiseHost: "::", hostIP: net.ParseIP("192.0.2.10"), wantErr: true},
		{name: "pod named kubelet is ignored", kubeletArgs: []string{"--node-ip=192.0.2.30"}, podArgs: []string{"--node-ip=203.0.113.9"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.30\n"},
		{name: "pod named kubelet does not replace the default route", podArgs: []string{"--node-ip=203.0.113.9"}, hostIP: net.ParseIP("192.0.2.10"), want: "192.0.2.10\n"},
		{name: "no address keeps the stale file", hostErr: errors.New("no route"), want: stale, wantErr: true},
		{name: "failed write keeps the stale file", hostIP: net.ParseIP("192.0.2.10"), writeErr: errors.New("disk full"), want: stale, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeHostInterface(t, tc.hostIP, tc.hostErr)
			if tc.writeErr != nil {
				orig := writeNodeIPFile
				writeNodeIPFile = func(string, []byte, os.FileMode) error { return tc.writeErr }
				t.Cleanup(func() { writeNodeIPFile = orig })
			}
			cfg := &config{}
			cfg.WorkloadClaims.SocketDir = t.TempDir()
			cfg.WorkloadClaims.AdvertiseHost = tc.advertiseHost
			cfg.WorkloadClaims.ProcRoot = kubeletProc(t, tc.kubeletArgs, tc.podArgs)
			path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
			if err := os.WriteFile(path, []byte(stale), 0o644); err != nil {
				t.Fatal(err)
			}
			mounted := filepath.Join(t.TempDir(), "mounted")
			if err := os.Link(path, mounted); err != nil {
				t.Fatal(err)
			}
			p := &nodeIPPublisher{cfg: cfg, logger: slog.New(slog.DiscardHandler)}
			p.publish()
			if wait := p.publish(); (wait != nodeIPRecheckInterval) != tc.wantErr {
				t.Fatalf("publish() waits %v, want failure %t", wait, tc.wantErr)
			}
			for _, f := range []string{path, mounted} {
				if got, err := os.ReadFile(f); err != nil || string(got) != tc.want {
					t.Errorf("%s = %q, %v; want %q", filepath.Base(f), got, err, tc.want)
				}
			}
			if tc.want == "" {
				return
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("stat node-ip = %v, %v; want mode 0644", info, err)
			}
		})
	}
}

func fakeHostInterface(t *testing.T, ip net.IP, err error) {
	t.Helper()
	orig := chooseHostInterface
	chooseHostInterface = func() (net.IP, error) { return ip, err }
	t.Cleanup(func() { chooseHostInterface = orig })
}

// A kubelet restarting with --node-ip is briefly absent from proc. The
// default route may name another interface, which must not replace the
// kubelet's address in the meantime.
func TestNodeIPPublisherKeepsKubeletAddressWhileItIsAbsent(t *testing.T) {
	fakeHostInterface(t, net.ParseIP("192.0.2.10"), nil)
	cfg := &config{}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	withKubelet := kubeletProc(t, []string{"--node-ip=192.0.2.30"}, nil)
	cfg.WorkloadClaims.ProcRoot = withKubelet
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
	p := &nodeIPPublisher{cfg: cfg, logger: slog.New(slog.DiscardHandler)}

	p.publish()
	cfg.WorkloadClaims.ProcRoot = kubeletProc(t, nil, nil)
	for range 3 {
		if wait := p.publish(); wait != nodeIPRecheckInterval {
			t.Fatalf("recheck without the kubelet waits %v, want the recheck interval", wait)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != "192.0.2.30\n" {
			t.Fatalf("node-ip without the kubelet = %q, %v; want the kubelet's 192.0.2.30", got, err)
		}
	}
}

// A failed write leaves the published address in place, and the next
// recheck that writes publishes the address it resolved.
func TestNodeIPPublisherSurvivesTransientWriteFailure(t *testing.T) {
	shrinkRetries(t)
	fakeHostInterface(t, net.ParseIP("192.0.2.10"), nil)
	cfg := &config{}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	cfg.WorkloadClaims.ProcRoot = kubeletProc(t, nil, nil)
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
	p := &nodeIPPublisher{cfg: cfg, logger: slog.New(slog.DiscardHandler)}
	p.publish()

	fakeHostInterface(t, net.ParseIP("192.0.2.11"), nil)
	orig := writeNodeIPFile
	writeNodeIPFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	p.publish()
	if wait := p.publish(); wait != nodeRetryMinDelay {
		t.Fatalf("failed publish() waits %v, want the retry delay %v", wait, nodeRetryMinDelay)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "192.0.2.10\n" {
		t.Fatalf("node-ip after a failed write = %q, %v; want the last address 192.0.2.10", got, err)
	}
	writeNodeIPFile = orig
	if wait := p.publish(); wait != nodeIPRecheckInterval {
		t.Fatalf("publish() after the write recovers waits %v, want the recheck interval", wait)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "192.0.2.11\n" {
		t.Fatalf("node-ip after recovery = %q, %v; want 192.0.2.11", got, err)
	}
}

// kubeletProc is a proc root with an unrelated process and, when args is not
// nil, a host kubelet running with them. When podArgs is not nil, a pod process
// that named itself kubelet runs with them at a PID ReadDir lists first.
func kubeletProc(t *testing.T, args, podArgs []string) string {
	t.Helper()
	root := t.TempDir()
	write := func(pid, name, content string) {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mountNS := func(pid, ns string) {
		if err := os.MkdirAll(filepath.Join(root, pid, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(root, pid, "ns", "mnt")); err != nil {
			t.Fatal(err)
		}
	}
	write("1", "comm", "systemd\n")
	write("1", "cmdline", "/sbin/init\x00--node-ip=198.51.100.1\x00")
	mountNS("1", "mnt:[4026531841]")
	if args != nil {
		write("42", "comm", "kubelet\n")
		write("42", "cmdline", "kubelet\x00"+strings.Join(args, "\x00")+"\x00")
		mountNS("42", "mnt:[4026531841]")
	}
	if podArgs != nil {
		write("10001", "comm", "kubelet\n")
		write("10001", "cmdline", "sh\x00"+strings.Join(podArgs, "\x00")+"\x00")
		mountNS("10001", "mnt:[4026532999]")
	}
	return root
}

// A DHCP node may have no default route when containerd starts the plugin, and
// its address may change later: the file follows both, a change once it held
// for two rechecks.
func TestNodeIPPublisherRetriesAndFollowsChanges(t *testing.T) {
	shrinkRetries(t)
	var answer net.IP
	orig := chooseHostInterface
	chooseHostInterface = func() (net.IP, error) {
		if answer == nil {
			return nil, errors.New("no default route yet")
		}
		return answer, nil
	}
	t.Cleanup(func() { chooseHostInterface = orig })
	cfg := &config{}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	cfg.WorkloadClaims.ProcRoot = kubeletProc(t, nil, nil)
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
	p := &nodeIPPublisher{cfg: cfg, logger: slog.New(slog.DiscardHandler)}

	if wait := p.publish(); wait != nodeRetryMinDelay {
		t.Fatalf("publish() with no route waits %v, want the retry delay %v", wait, nodeRetryMinDelay)
	}
	if wait := p.publish(); wait != 2*nodeRetryMinDelay {
		t.Fatalf("second failed publish() waits %v, want %v", wait, 2*nodeRetryMinDelay)
	}
	// The first address is published at once; a change waits one recheck.
	for _, step := range []struct{ answer, want string }{
		{"192.0.2.10", "192.0.2.10"},
		{"192.0.2.11", "192.0.2.10"},
		{"192.0.2.12", "192.0.2.10"},
		{"192.0.2.12", "192.0.2.12"},
	} {
		answer = net.ParseIP(step.answer)
		if wait := p.publish(); wait != nodeIPRecheckInterval {
			t.Fatalf("publish() of %s waits %v, want the recheck interval %v", step.answer, wait, nodeIPRecheckInterval)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != step.want+"\n" {
			t.Fatalf("node-ip after resolving %s = %q, %v; want %s", step.answer, got, err, step.want)
		}
	}
}

// The signer must not stop the plugin when the node address is not there yet:
// it retries, and issuance starts once the address is published.
func TestInitSandboxTokensRetries(t *testing.T) {
	shrinkRetries(t)
	t.Setenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST", "")
	cfg := &config{}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	cfg.Allowlist.Pull.URL = "https://127.0.0.1:30808"

	attempts := make(chan error, 100)
	orig := newSandboxTokenSigner
	newSandboxTokenSigner = func(cfg *config, logger *slog.Logger) (*workloadclaims.SandboxTokenSigner, error) {
		s, err := orig(cfg, logger)
		attempts <- err
		return s, err
	}
	t.Cleanup(func() { newSandboxTokenSigner = orig })

	var signer atomic.Pointer[workloadclaims.SandboxTokenSigner]
	served := make(chan *workloadclaims.SandboxTokenSigner, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		initSandboxTokens(ctx, slog.New(slog.DiscardHandler), cfg, &signer, func(s *workloadclaims.SandboxTokenSigner) error {
			served <- s
			return errors.New("port 1019 unavailable")
		})
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })

	for range 2 {
		if err := <-attempts; err == nil {
			t.Fatal("signer initialized with no node address")
		}
	}
	if signer.Load() != nil {
		t.Fatal("signer stored after failed attempts")
	}
	if err := os.WriteFile(filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile), []byte("192.0.2.10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := <-served
	cancel()
	<-done
	if signer.Load() != s {
		t.Fatalf("signer = %v, want the one the digests endpoint was started with", signer.Load())
	}
}

// Tokens name the address node-ip holds now, under the key the digests
// endpoint already serves, and keep the last address when there is none.
func TestFollowSandboxHost(t *testing.T) {
	t.Setenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST", "")
	cfg := &config{}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	cfg.Allowlist.Pull.URL = "https://127.0.0.1:30808"
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
	logger := slog.New(slog.DiscardHandler)

	first, err := workloadclaims.NewSandboxTokenSigner("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	var signer atomic.Pointer[workloadclaims.SandboxTokenSigner]
	signer.Store(first)
	requester, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requesterDigest, err := workloadclaims.RequesterKeyDigest(&requester.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, file, want string
	}{
		{"unchanged", "192.0.2.10\n", "192.0.2.10"},
		{"changed", "192.0.2.11\n", "192.0.2.11"},
		{"emptied keeps the last address", "", "192.0.2.11"},
	} {
		if err := os.WriteFile(path, []byte(tc.file), 0o644); err != nil {
			t.Fatal(err)
		}
		followSandboxHost(cfg, logger, &signer, true)
		s := signer.Load()
		if s.Host() != tc.want {
			t.Errorf("%s: host = %s, want %s", tc.name, s.Host(), tc.want)
		}
		if !bytes.Equal(s.PublicKeyDER(), first.PublicKeyDER()) {
			t.Errorf("%s: the key changed, so the digests endpoint no longer serves it", tc.name)
		}
		nonce := []byte("nonce")
		tok, err := s.Sign("sandbox", requesterDigest, nonce)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := tok.Verify(first.PublicKey(), &requester.PublicKey, nonce)
		if err != nil || verified.InventoryHost != tc.want {
			t.Errorf("%s: token names %q, %v; want %s", tc.name, verified.InventoryHost, err, tc.want)
		}
	}
}

func shrinkRetries(t *testing.T) {
	t.Helper()
	minDelay, maxDelay, recheck := nodeRetryMinDelay, nodeRetryMaxDelay, nodeIPRecheckInterval
	nodeRetryMinDelay, nodeRetryMaxDelay, nodeIPRecheckInterval = time.Millisecond, 4*time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { nodeRetryMinDelay, nodeRetryMaxDelay, nodeIPRecheckInterval = minDelay, maxDelay, recheck })
}

// The recheck runs every minute: an address that stays unresolved warns once,
// and again only after it resolved in between.
func TestFollowSandboxHostWarnsOnStateChange(t *testing.T) {
	t.Setenv("C8S_SANDBOX_DIGESTS_ADVERTISE_HOST", "")
	cfg := &config{}
	cfg.WorkloadClaims.SocketDir = t.TempDir()
	cfg.Allowlist.Pull.URL = "https://127.0.0.1:30808"
	path := filepath.Join(cfg.WorkloadClaims.SocketDir, NodeIPFile)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	first, err := workloadclaims.NewSandboxTokenSigner("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	var signer atomic.Pointer[workloadclaims.SandboxTokenSigner]
	signer.Store(first)

	ok := true
	for i, file := range []string{"", "", "192.0.2.11\n", "", ""} {
		if err := os.WriteFile(path, []byte(file), 0o644); err != nil {
			t.Fatal(err)
		}
		ok = followSandboxHost(cfg, logger, &signer, ok)
		if ok != (file != "") {
			t.Fatalf("recheck %d with node-ip %q: resolved = %t", i, file, ok)
		}
	}
	if got := strings.Count(logs.String(), "level=WARN"); got != 2 {
		t.Errorf("warnings = %d, want 2:\n%s", got, logs.String())
	}
}
