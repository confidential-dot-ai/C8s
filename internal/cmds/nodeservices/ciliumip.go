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
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Cilium reads its node IP from the Kubernetes Node object once, when the
// agent starts (pkg/node/sync initFromK8s), and announces it to the other
// nodes as this node's tunnel endpoint. A node that boots with a new address
// can start its agent before the kubelet has replaced the previous address
// in the Node's status; the agent then keeps the stale address for its whole
// life and the node's pods are unreachable. WatchCiliumNodeIP restarts such
// an agent so it reads the now current Node.

const (
	ciliumSocket       = "/run/cilium/cilium.sock"
	ciliumPollInterval = 10 * time.Second
)

// ciliumBackoff is the pause after each consecutive restart; the last entry
// repeats until the agent announces the node's address again.
var ciliumBackoff = []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute}

// localAddrs is a package var so tests can fake the host's interfaces.
var localAddrs = func() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out, nil
}

// signalAgent is a package var so tests can count restarts.
var signalAgent = func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }

// WatchCiliumNodeIP runs until ctx ends. RootDir only rebases the fixed
// host paths for tests.
func WatchCiliumNodeIP(ctx context.Context, rootDir string) error {
	w := ciliumWatch{rootDir: rootDir}
	ticker := time.NewTicker(ciliumPollInterval)
	defer ticker.Stop()
	for {
		w.step(ctx, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type ciliumWatch struct {
	rootDir    string
	restarts   int
	quietUntil time.Time
}

func (w *ciliumWatch) step(ctx context.Context, now time.Time) {
	switch state, announced, nodeIP := ciliumNodeIPState(ctx, w.rootDir); state {
	case ciliumCurrent:
		w.restarts, w.quietUntil = 0, time.Time{}
	case ciliumStale:
		if now.Before(w.quietUntil) || !restartCiliumAgent(w.rootDir, announced, nodeIP) {
			return
		}
		w.quietUntil = now.Add(ciliumBackoff[min(w.restarts, len(ciliumBackoff)-1)])
		w.restarts++
	}
}

type ciliumState int

const (
	// ciliumUnknown: no published node address, agent API not answering,
	// or the agent announces another address of this node.
	ciliumUnknown ciliumState = iota
	// ciliumCurrent: the agent announces the published node address.
	ciliumCurrent
	// ciliumStale: the agent announces an address that is neither the
	// published node address nor assigned to any local interface.
	ciliumStale
)

func ciliumNodeIPState(ctx context.Context, rootDir string) (state ciliumState, announced, nodeIP netip.Addr) {
	data, err := os.ReadFile(filepath.Join(rootDir, nodeIPPath))
	if err != nil {
		return ciliumUnknown, announced, nodeIP
	}
	if nodeIP, err = netip.ParseAddr(strings.TrimSpace(string(data))); err != nil {
		return ciliumUnknown, announced, nodeIP
	}
	if announced, err = ciliumNodeIP(ctx, filepath.Join(rootDir, ciliumSocket)); err != nil {
		return ciliumUnknown, announced, nodeIP
	}
	if announced == nodeIP {
		return ciliumCurrent, announced, nodeIP
	}
	local, err := localAddrs()
	if err != nil {
		return ciliumUnknown, announced, nodeIP
	}
	for _, a := range local {
		if a == announced {
			return ciliumUnknown, announced, nodeIP
		}
	}
	return ciliumStale, announced, nodeIP
}

// restartCiliumAgent sends SIGTERM to the Cilium pod's agent; the kubelet
// restarts the container and the new agent reads the current Node.
func restartCiliumAgent(rootDir string, announced, nodeIP netip.Addr) (restarted bool) {
	pids, err := ciliumAgentPIDs(filepath.Join(rootDir, "/proc"))
	if err != nil || len(pids) == 0 {
		slog.Warn("cilium-agent announces a node IP this node does not have, but its process was not found",
			"old_ip", announced, "new_ip", nodeIP, "err", err)
		return false
	}
	for _, pid := range pids {
		if err := signalAgent(pid); err != nil {
			slog.Warn("signal cilium-agent", "pid", pid, "err", err)
			continue
		}
		slog.Warn(fmt.Sprintf("restarting cilium-agent: stale node IP %s -> %s", announced, nodeIP),
			"old_ip", announced, "new_ip", nodeIP, "pid", pid)
		restarted = true
	}
	return restarted
}

// ciliumNodeIP asks the agent's local API for the IPv4 address it announces
// for this node.
func ciliumNodeIP(ctx context.Context, socket string) (netip.Addr, error) {
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
	inodes, err := listeningSocketInodes(filepath.Join(proc, "net", "unix"), ciliumSocket)
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
		if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err != nil || strings.TrimSpace(string(comm)) != "cilium-agent" {
			continue
		}
		if cg, err := os.ReadFile(filepath.Join(dir, "cgroup")); err != nil || !strings.Contains(string(cg), "kubepods") {
			continue
		}
		if holdsSocket(filepath.Join(dir, "fd"), inodes) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// listeningSocketInodes returns the inodes of listening unix sockets bound
// at a path ending in suffix (the agent binds /var/run/cilium/cilium.sock in
// its own mount namespace).
func listeningSocketInodes(netUnix, suffix string) (map[string]bool, error) {
	f, err := os.Open(netUnix)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const acceptConn = 0x10000
	inodes := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		// Num RefCount Protocol Flags Type St Inode Path
		fields := strings.Fields(s.Text())
		if len(fields) < 8 || !strings.HasSuffix(fields[7], suffix) {
			continue
		}
		if flags, err := strconv.ParseUint(fields[3], 16, 32); err == nil && flags&acceptConn != 0 {
			inodes[fields[6]] = true
		}
	}
	return inodes, s.Err()
}

func holdsSocket(fdDir string, inodes map[string]bool) bool {
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") && inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] {
			return true
		}
	}
	return false
}
