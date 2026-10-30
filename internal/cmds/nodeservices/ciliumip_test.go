package nodeservices

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

const (
	staleIP   = "192.0.2.99"
	currentIP = "192.0.2.10"
)

// fakeCiliumNode serves the agent's /v1/cluster/nodes on the agent socket
// under root, announcing announced as the local node's address.
func fakeCiliumNode(t *testing.T, root, announced string) {
	t.Helper()
	socket := filepath.Join(root, ciliumSocket)
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/cluster/nodes" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"self": "default/node-a",
			"nodes-added": []any{
				map[string]any{"name": "default/node-b", "primary-address": map[string]any{"ipv4": map[string]any{"ip": "192.0.2.20"}}},
				map[string]any{"name": "default/node-a", "primary-address": map[string]any{"ipv4": map[string]any{"ip": announced}}},
			},
		})
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
}

func publishNodeIP(t *testing.T, root, ip string) {
	t.Helper()
	writeInput(t, root, nodeIPPath, []byte(ip+"\n"))
}

// watchWithLocalAddrs builds a watch on root whose host interfaces are addrs.
func watchWithLocalAddrs(root string, addrs ...string) *ciliumWatch {
	w := newCiliumWatch(root)
	w.localAddrs = func() ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	return w
}

// process is a real child whose fake /proc entry under root has the given
// comm, cgroup and socket fd.
type process struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startProcess(t *testing.T, root, comm, cgroup, socketInode string) *process {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() { cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { cmd.Process.Kill(); <-p.done })
	dir := filepath.Join(root, "proc", strconv.Itoa(cmd.Process.Pid))
	writeInput(t, root, filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "comm"), []byte(comm+"\n"))
	writeInput(t, root, filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "cgroup"), []byte("0::"+cgroup+"\n"))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+socketInode+"]", filepath.Join(dir, "fd", "7")); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *process) exited(wait time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(wait):
		return false
	}
}

const podCgroup = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-abc.scope"

// fakeAgentProcesses lays out /proc/net/unix with the agent's listening API
// socket (inode 111) and a connected client end on the same path (222), and
// starts the agent plus two look-alikes that must never be signalled.
func fakeAgentProcesses(t *testing.T, root string) (agent, outsidePod, notListening *process) {
	t.Helper()
	writeInput(t, root, "/proc/net/unix", []byte(
		"Num       RefCount Protocol Flags    Type St Inode Path\n"+
			"0000000000000000: 00000002 00000000 00010000 0001 01 111 /var/run/cilium/cilium.sock\n"+
			"0000000000000000: 00000003 00000000 00000000 0001 03 222 /var/run/cilium/cilium.sock\n"+
			"0000000000000000: 00000002 00000000 00010000 0001 01 333 /run/other.sock\n"))
	agent = startProcess(t, root, "cilium-agent", podCgroup, "111")
	outsidePod = startProcess(t, root, "cilium-agent", "/system.slice/fake.service", "111")
	notListening = startProcess(t, root, "cilium-agent", podCgroup, "222")
	startProcess(t, root, "sleep", podCgroup, "111")
	return agent, outsidePod, notListening
}

// After a reboot with a new address, the agent still announces the previous
// one. The watch must restart exactly that agent.
func TestCiliumNodeIPRestartsAgentWithStaleAddress(t *testing.T) {
	root := t.TempDir()
	publishNodeIP(t, root, currentIP)
	fakeCiliumNode(t, root, staleIP)
	agent, outsidePod, notListening := fakeAgentProcesses(t, root)
	w := watchWithLocalAddrs(root, "127.0.0.1", currentIP)

	verdict, addrs := w.announcement(context.Background())
	if verdict != announcesForeignAddress || addrs.announced.String() != staleIP || addrs.published.String() != currentIP {
		t.Fatalf("announcement = %v, %v; want a foreign address %s with %s published", verdict, addrs, staleIP, currentIP)
	}
	if !w.restartAgents(addrs) {
		t.Fatal("restartAgents found no agent to restart")
	}
	if !agent.exited(5 * time.Second) {
		t.Fatal("the cilium-agent announcing a stale node IP was not restarted")
	}
	if outsidePod.exited(200*time.Millisecond) || notListening.exited(200*time.Millisecond) {
		t.Fatal("signalled a cilium-agent look-alike that is not the pod's API server")
	}
}

func TestCiliumNodeIPLeavesAgentAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		nodeIP, announced string
		local             []string
		noSocket          bool
		want              ciliumVerdict
	}{
		"current address":           {nodeIP: currentIP, announced: currentIP, local: []string{currentIP}, want: announcesNodeAddress},
		"another local address":     {nodeIP: currentIP, announced: "198.51.100.7", local: []string{currentIP, "198.51.100.7"}},
		"no published node address": {announced: staleIP, local: []string{currentIP}},
		"agent API not up":          {nodeIP: currentIP, announced: staleIP, local: []string{currentIP}, noSocket: true},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if tc.nodeIP != "" {
				publishNodeIP(t, root, tc.nodeIP)
			}
			if !tc.noSocket {
				fakeCiliumNode(t, root, tc.announced)
			}
			agent, _, _ := fakeAgentProcesses(t, root)
			w := watchWithLocalAddrs(root, tc.local...)
			w.step(context.Background(), time.Now())
			if verdict, _ := w.announcement(context.Background()); verdict != tc.want {
				t.Fatalf("announcement = %v, want %v", verdict, tc.want)
			}
			if agent.exited(200 * time.Millisecond) {
				t.Fatal("restarted an agent without a stale address")
			}
		})
	}
}

func TestCiliumNodeIPBackoff(t *testing.T) {
	root := t.TempDir()
	publishNodeIP(t, root, currentIP)
	announced := staleIP
	socket := filepath.Join(root, ciliumSocket)
	os.MkdirAll(filepath.Dir(socket), 0o755)
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"self":"n","nodes-added":[{"name":"n","primary-address":{"ipv4":{"ip":%q}}}]}`, announced)
	})}
	go srv.Serve(l)
	defer srv.Close()
	fakeAgentProcesses(t, root)
	signals := 0
	w := watchWithLocalAddrs(root, currentIP)
	w.signalAgent = func(int) error {
		signals++
		return nil
	}

	ctx := context.Background()
	restarts := 0
	restart := func(at time.Time) {
		w.step(ctx, at)
		restarts++
		if signals != restarts {
			t.Fatalf("%d restarts, want %d", signals, restarts)
		}
	}
	staysQuiet := func(at time.Time) {
		w.step(ctx, at)
		if signals != restarts {
			t.Fatalf("%d restarts during a pause, want %d", signals, restarts)
		}
	}

	at := time.Now()
	restart(at)
	// Each restart pauses for the next back-off entry; the last entry repeats.
	for _, pause := range append(slices.Clone(ciliumBackoff), ciliumBackoff[len(ciliumBackoff)-1]) {
		staysQuiet(at.Add(pause - time.Second))
		at = at.Add(pause)
		restart(at)
	}

	// An announcement of the node address, even inside a pause, starts the
	// back-off over.
	announced = currentIP
	w.step(ctx, at.Add(time.Second))
	announced = staleIP
	at = at.Add(2 * time.Second)
	restart(at)
	staysQuiet(at.Add(ciliumBackoff[0] - time.Second))
	restart(at.Add(ciliumBackoff[0]))
}
