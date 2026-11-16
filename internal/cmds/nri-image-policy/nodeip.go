package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
)

// Node-side retry timing; vars so tests can shrink them.
var (
	nodeRetryMinDelay     = time.Second
	nodeRetryMaxDelay     = time.Minute
	nodeIPRecheckInterval = time.Minute
)

// chooseHostInterface and writeNodeIPFile are package vars so tests can fake
// the host's routes and a failed write.
var (
	chooseHostInterface = utilnet.ChooseHostInterface
	writeNodeIPFile     = writeInPlace
)

// nodeIPPublisher keeps NodeIPFile current: a DHCP node may have no default
// route when containerd starts, and its address may change later. Components
// restart when the file names another address, and a restarted CDS that
// reads it regenerates the mesh CA, so a transient failure never touches the
// file and a change is published only once it held for two rechecks. A
// resolver that alternates between two addresses therefore never publishes.
type nodeIPPublisher struct {
	cfg    *config
	logger *slog.Logger
	delay  time.Duration // current failure backoff, 0 after a success

	kubelet string // the last address a host kubelet's --node-ip supplied
	pending string // a changed address seen once, published if it holds
	settled bool   // the file holds an address this process resolved
}

// publish makes one attempt and returns the wait before the next: the recheck
// interval after a success, a doubling backoff after a failure.
func (p *nodeIPPublisher) publish() time.Duration {
	path := filepath.Join(p.cfg.WorkloadClaims.SocketDir, NodeIPFile)
	host, source, err := p.resolve()
	if err == nil && !usableNodeIP(net.ParseIP(host)) {
		// Not transient: advertise_host names an address no pod can dial.
		p.pending = ""
		p.delay = min(max(2*p.delay, nodeRetryMinDelay), nodeRetryMaxDelay)
		p.logger.Error("node-ip emptied: the node address is not a unicast address other pods can dial; running components keep the address they read, and components that start will not until an address is published",
			"address", host, "source", source, "error", emptyIfExists(path), "retry_in", p.delay)
		return p.delay
	}
	if err == nil {
		err = p.write(path, host, source)
	}
	if err != nil {
		p.delay = min(max(2*p.delay, nodeRetryMinDelay), nodeRetryMaxDelay)
		p.logger.Error("node-ip not updated; it keeps its last address, and components that read none will not start until it is published", "error", err, "retry_in", p.delay)
		return p.delay
	}
	p.delay = 0
	return nodeIPRecheckInterval
}

// write publishes host unless the file holds it already. A file naming
// another address keeps it until a second recheck resolves host again. The
// first write of a process skips that wait unless host came from the default
// route: the file then predates this process, while a default route seen
// before the kubelet is back from a node restart may name another interface.
func (p *nodeIPPublisher) write(path, host, source string) error {
	current := ""
	if b, err := os.ReadFile(path); err == nil {
		current = strings.TrimSpace(string(b))
	}
	if current == host {
		p.pending = ""
		p.settled = true
		return nil
	}
	debounce := p.settled || source == "default_route"
	if current != "" && debounce && p.pending != host {
		p.pending = host
		p.logger.Warn("node address changed; publishing it if the next recheck agrees", "address", host, "source", source, "published", current, "recheck_in", nodeIPRecheckInterval)
		return nil
	}
	if err := writeNodeIP(path, host); err != nil {
		return err
	}
	p.pending = ""
	p.settled = true
	p.logger.Info("node-ip published", "address", host, "source", source)
	return nil
}

// resolve returns the node's address and the source that supplied it:
// advertise_host when it is an IP, else the --node-ip of a kubelet in the
// host's mount namespace, which is the Node's registered InternalIP and its
// pods' status.hostIP, else the default-route interface's address, which a
// kubelet without --node-ip usually registers. Once a kubelet supplied an
// address, a recheck that finds no kubelet keeps it rather than fall back to
// the default route: the kubelet is restarting, and its address has not
// changed. k3s runs its kubelet inside the k3s process, so a k3s node with
// several interfaces needs advertise_host. A pod could otherwise pick the
// attestation verifier components dial.
func (p *nodeIPPublisher) resolve() (host, source string, err error) {
	if host := p.cfg.WorkloadClaims.AdvertiseHost; net.ParseIP(host) != nil {
		return host, "advertise_host", nil
	}
	host, running := kubeletNodeIP(p.cfg.WorkloadClaims.ProcRoot)
	switch {
	case host != "":
		p.kubelet = host
		return host, "kubelet", nil
	case running:
		// A kubelet that runs without a usable --node-ip picks its address
		// as the default route does.
		p.kubelet = ""
	case p.kubelet != "":
		return p.kubelet, "kubelet_last_seen", nil
	}
	ip, err := chooseHostInterface()
	if err != nil {
		return "", "", fmt.Errorf("resolve node address: %w", err)
	}
	if !usableNodeIP(ip) {
		// Likely a link-local address before DHCP completes: retry.
		return "", "", fmt.Errorf("resolve node address: default route address %s is not one other pods can dial", ip)
	}
	return ip.String(), "default_route", nil
}

// run repeats publish until ctx is done, waiting wait before the first attempt.
func (p *nodeIPPublisher) run(ctx context.Context, wait time.Duration) {
	for sleepCtx(ctx, wait) {
		wait = p.publish()
	}
}

// kubeletNodeIP is the first address of a host kubelet's --node-ip flag, read
// from procRoot (default /proc), or "" when no host kubelet passes a usable
// one; running reports whether a host kubelet runs at all. A pod's processes
// show up in procRoot too and can name themselves kubelet, but cannot join
// the host's mount namespace, which is init's. --node-ip=:: or 0.0.0.0
// selects an address family, not an address.
func kubeletNodeIP(procRoot string) (host string, running bool) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	hostMounts, err := os.Readlink(filepath.Join(procRoot, "1", "ns", "mnt"))
	if err != nil {
		return "", false
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		comm, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "kubelet" {
			continue
		}
		if mounts, err := os.Readlink(filepath.Join(dir, "ns", "mnt")); err != nil || mounts != hostMounts {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		running = true
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		for i, arg := range args {
			value, ok := strings.CutPrefix(arg, "--node-ip=")
			if !ok && arg == "--node-ip" && i+1 < len(args) {
				value, ok = args[i+1], true
			}
			if !ok {
				continue
			}
			first, _, _ := strings.Cut(value, ",")
			if ip := net.ParseIP(first); usableNodeIP(ip) {
				return ip.String(), true
			}
		}
	}
	return "", running
}

// usableNodeIP reports whether components can dial ip as the node: an
// unspecified or loopback address reaches the dialing pod's own network
// namespace instead.
func usableNodeIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast()
}

// writeNodeIP writes host to path in place: components bind-mount the file
// itself, so a renamed replacement would leave their mount on the old inode.
// A write can fail after it changed the file, so a failed one puts the
// previous content back, or empties a file that held none.
func writeNodeIP(path, host string) error {
	previous, readErr := os.ReadFile(path)
	// World-readable: non-root components read it.
	err := writeNodeIPFile(path, []byte(host+"\n"), 0o644)
	if err == nil {
		return nil
	}
	err = fmt.Errorf("write %s: %w", path, err)
	if readErr != nil {
		return errors.Join(err, emptyIfExists(path))
	}
	if restoreErr := writeNodeIPFile(path, previous, 0o644); restoreErr != nil {
		return errors.Join(err, fmt.Errorf("restore %s: %w", path, restoreErr))
	}
	return err
}

// writeInPlace replaces path's content without replacing its inode, so a bind
// mount of the file sees the change. A reader may see a partial write;
// cmdsutil.WatchNodeIP acts only on a value it reads twice.
func writeInPlace(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	_, err = f.WriteAt(data, 0)
	if err == nil {
		err = f.Truncate(int64(len(data)))
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	return errors.Join(err, f.Close())
}

func emptyIfExists(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.Join(f.Truncate(0), f.Close())
}
