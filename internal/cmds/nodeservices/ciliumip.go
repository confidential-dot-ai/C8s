package nodeservices

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Cilium reads its node IP from the Kubernetes Node object once, when the
// agent starts (pkg/node/sync initFromK8s), and announces it to the other
// nodes as this node's tunnel endpoint. An agent that starts before the
// kubelet publishes a new address keeps the previous one for its whole life,
// and the node's pods are unreachable. WatchCiliumNodeIP restarts such an
// agent so it reads the current Node.

const (
	ciliumSocket = "/run/cilium/cilium.sock"
	// The agent binds its API socket in its own mount namespace, at a path
	// ending in this.
	ciliumSocketSuffix = "/cilium/cilium.sock"
	ciliumPollInterval = 10 * time.Second
)

// ciliumBackoff is the pause after each consecutive restart; the last entry
// repeats until the agent announces the node's address again.
var ciliumBackoff = []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute}

func hostAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			return nil, fmt.Errorf("interface address %q: %w", a, err)
		}
		out = append(out, prefix.Addr().Unmap())
	}
	return out, nil
}

// WatchCiliumNodeIP runs until ctx ends. rootDir only rebases the fixed
// host paths for tests.
func WatchCiliumNodeIP(ctx context.Context, rootDir string) {
	w := newCiliumWatch(rootDir)
	ticker := time.NewTicker(ciliumPollInterval)
	defer ticker.Stop()
	for {
		w.step(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type ciliumWatch struct {
	rootDir     string
	localAddrs  func() ([]netip.Addr, error)
	signalAgent func(pid int) error
	restarts    int
	quietUntil  time.Time
}

func newCiliumWatch(rootDir string) *ciliumWatch {
	return &ciliumWatch{
		rootDir:     rootDir,
		localAddrs:  hostAddrs,
		signalAgent: func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) },
	}
}

func (w *ciliumWatch) step(ctx context.Context, now time.Time) {
	verdict, addrs := w.announcement(ctx)
	switch verdict {
	case noVerdict:
	case announcesNodeAddress:
		w.restarts = 0
		w.quietUntil = time.Time{}
	case announcesForeignAddress:
		w.restartUnlessPaused(now, addrs)
	}
}

func (w *ciliumWatch) restartUnlessPaused(now time.Time, addrs nodeAddresses) {
	if now.Before(w.quietUntil) {
		return
	}
	if !w.restartAgents(addrs) {
		return
	}
	w.quietUntil = now.Add(w.pauseAfterRestart())
	w.restarts++
}

// pauseAfterRestart walks ciliumBackoff with each consecutive restart and
// stays on its last entry.
func (w *ciliumWatch) pauseAfterRestart() time.Duration {
	return ciliumBackoff[min(w.restarts, len(ciliumBackoff)-1)]
}

// ciliumVerdict compares the address the local agent announces for this node
// with the address published for the node.
type ciliumVerdict int

const (
	// noVerdict: no published node address, no answer from the agent, or an
	// announced address this node holds on another interface.
	noVerdict ciliumVerdict = iota
	announcesNodeAddress
	announcesForeignAddress
)

// nodeAddresses pairs what the agent announces for this node with what is
// published for it. It is filled only for announcesForeignAddress.
type nodeAddresses struct {
	announced netip.Addr
	published netip.Addr
}

func (w *ciliumWatch) announcement(ctx context.Context) (ciliumVerdict, nodeAddresses) {
	published, err := w.publishedNodeAddress()
	if err != nil {
		return noVerdict, nodeAddresses{}
	}
	announced, err := announcedIPv4(ctx, filepath.Join(w.rootDir, ciliumSocket))
	if err != nil {
		return noVerdict, nodeAddresses{}
	}
	if announced == published {
		return announcesNodeAddress, nodeAddresses{}
	}
	local, err := w.localAddrs()
	if err != nil {
		return noVerdict, nodeAddresses{}
	}
	if slices.Contains(local, announced) {
		return noVerdict, nodeAddresses{}
	}
	return announcesForeignAddress, nodeAddresses{announced: announced, published: published}
}

func (w *ciliumWatch) publishedNodeAddress() (netip.Addr, error) {
	data, err := os.ReadFile(filepath.Join(w.rootDir, nodeIPPath))
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(string(data)))
}

// restartAgents sends SIGTERM to every agent process of this node's Cilium
// pod; the kubelet restarts the container and the new agent reads the
// current Node.
func (w *ciliumWatch) restartAgents(addrs nodeAddresses) (restarted bool) {
	pids, err := ciliumAgentPIDs(filepath.Join(w.rootDir, "/proc"))
	if err != nil || len(pids) == 0 {
		slog.Warn("cilium-agent announces an address this node does not have, but its process was not found",
			"announced", addrs.announced, "published", addrs.published, "err", err)
		return false
	}
	for _, pid := range pids {
		if err := w.signalAgent(pid); err != nil {
			slog.Warn("signal cilium-agent", "pid", pid, "err", err)
			continue
		}
		slog.Warn("restarting cilium-agent: it announces an address this node does not have",
			"announced", addrs.announced, "published", addrs.published, "pid", pid)
		restarted = true
	}
	return restarted
}

// announcedIPv4 asks the agent's local API for the IPv4 address it announces
// for this node.
func announcedIPv4(ctx context.Context, socket string) (netip.Addr, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://cilium/v1/cluster/nodes", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("cilium API: %s", resp.Status)
	}
	var status struct {
		Self  string `json:"self"`
		Nodes []struct {
			Name    string `json:"name"`
			Primary struct {
				IPv4 struct {
					IP string `json:"ip"`
				} `json:"ipv4"`
			} `json:"primary-address"`
		} `json:"nodes-added"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return netip.Addr{}, err
	}
	for _, n := range status.Nodes {
		if status.Self != "" && n.Name == status.Self {
			return netip.ParseAddr(n.Primary.IPv4.IP)
		}
	}
	return netip.Addr{}, fmt.Errorf("cilium API does not list the local node yet")
}

// ciliumAgentPIDs returns the processes named cilium-agent that run in a
// kubelet pod cgroup and hold the listening agent API socket.
func ciliumAgentPIDs(proc string) ([]int, error) {
	inodes, err := listeningSocketInodes(filepath.Join(proc, "net", "unix"), ciliumSocketSuffix)
	if err != nil || len(inodes) == 0 {
		return nil, err
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(proc, e.Name())
		if isCiliumAgent(dir) && inKubeletPod(dir) && holdsSocket(filepath.Join(dir, "fd"), inodes) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func isCiliumAgent(procDir string) bool {
	comm, err := os.ReadFile(filepath.Join(procDir, "comm"))
	return err == nil && strings.TrimSpace(string(comm)) == "cilium-agent"
}

func inKubeletPod(procDir string) bool {
	cgroup, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	return err == nil && strings.Contains(string(cgroup), "/kubepods")
}

// listeningSocketInodes returns the inodes of listening unix sockets bound at
// a path ending in suffix.
func listeningSocketInodes(netUnix, suffix string) (map[string]bool, error) {
	f, err := os.Open(netUnix)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	inodes := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 8 {
			continue
		}
		flags, inode, path := fields[3], fields[6], fields[7]
		if strings.HasSuffix(path, suffix) && listens(flags) {
			inodes[inode] = true
		}
	}
	return inodes, s.Err()
}

// listens reads the flags field of a /proc/net/unix line.
func listens(flags string) bool {
	const acceptConn = 0x10000
	parsed, err := strconv.ParseUint(flags, 16, 32)
	return err == nil && parsed&acceptConn != 0
}

func holdsSocket(fdDir string, inodes map[string]bool) bool {
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}
		if inodes[socketInode(target)] {
			return true
		}
	}
	return false
}

func socketInode(fdTarget string) string {
	if !strings.HasPrefix(fdTarget, "socket:[") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(fdTarget, "socket:["), "]")
}
