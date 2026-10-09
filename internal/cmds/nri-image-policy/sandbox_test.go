package nriimagepolicy

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	testPodUID     = "11111111-2222-3333-4444-555555555555"
	testSandboxID  = "abc123sandbox"
	testFloorImage = "floor@" + pushDigestA
)

// sandboxedPod is an ordinary pod: its own network, pid, ipc and uts
// namespaces, as containerd leaves them when the pod asks for none of the
// node's.
func sandboxedPod() *api.PodSandbox {
	return &api.PodSandbox{
		Id:        testSandboxID,
		Uid:       testPodUID,
		Name:      "pod",
		Namespace: "default",
		Linux: &api.LinuxPodSandbox{
			Namespaces: []*api.LinuxNamespace{
				{Type: "ipc", Path: "/proc/42/ns/ipc"},
				{Type: "network", Path: "/proc/42/ns/net"},
				{Type: "pid", Path: "/proc/42/ns/pid"},
				{Type: "uts", Path: "/proc/42/ns/uts"},
			},
		},
	}
}

// sandboxedContainer is an ordinary container: a cgroup namespace, read-only
// sysfs and cgroupfs, and only the mounts the kubelet and containerd stage
// under the pod's own directories.
func sandboxedContainer() *api.Container {
	return &api.Container{
		Id:   "ctr1",
		Name: "app",
		Mounts: []*api.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
			{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"nosuid", "noexec", "nodev", "relatime", "ro"}},
			{Destination: "/etc/hosts", Type: "bind", Source: "/var/lib/kubelet/pods/" + testPodUID + "/etc-hosts", Options: []string{"rbind", "rprivate", "rw"}},
			{Destination: "/etc/resolv.conf", Type: "bind", Source: "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/" + testSandboxID + "/resolv.conf"},
			{Destination: "/dev/shm", Type: "bind", Source: "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/" + testSandboxID + "/shm"},
			{Destination: "/var/run/secrets/kubernetes.io/serviceaccount", Type: "bind", Source: "/var/lib/kubelet/pods/" + testPodUID + "/volumes/kubernetes.io~projected/kube-api-access"},
		},
		Linux: &api.LinuxContainer{
			Namespaces: []*api.LinuxNamespace{
				{Type: "cgroup"},
				{Type: "ipc", Path: "/proc/42/ns/ipc"},
				{Type: "network", Path: "/proc/42/ns/net"},
			},
			SeccompPolicy: &api.LinuxSeccomp{DefaultAction: "SCMP_ACT_ERRNO"},
		},
	}
}

// injectedPod marks the pod as one the webhook injected sidecars into.
func injectedPod(p *api.PodSandbox) {
	p.Annotations = map[string]string{workloadclaims.AnnotationInjected: "true"}
}

// injectedPinsMount turns the container into a sidecar carrying the CDS policy
// mount sidecarAdjustment adds.
func injectedPinsMount(c *api.Container) {
	c.Name = workloadclaims.CertContainerName
	c.Mounts = append(c.Mounts, &api.Mount{
		Destination: workloadclaims.CDSPinsPath,
		Type:        "bind",
		Source:      "/run/c8s-node/cds.json",
		Options:     []string{"rbind", "ro", "rprivate", "nosuid", "nodev", "noexec"},
	})
}

// injectedSocketMount turns the container into a sidecar carrying the mount
// sidecarAdjustment adds.
func injectedSocketMount(c *api.Container) {
	c.Name = workloadclaims.CertContainerName
	c.Mounts = append(c.Mounts, &api.Mount{
		Destination: workloadclaims.SidecarSocketDir,
		Type:        "bind",
		Source:      "/var/run/nri-image-policy",
		Options:     []string{"rbind", "ro", "rprivate", "nosuid", "nodev", "noexec"},
	})
}

func TestSandboxViolations(t *testing.T) {
	tests := []struct {
		name      string
		pod       func(*api.PodSandbox)
		ctr       func(*api.Container)
		ownSocket string
		ownPins   string
		want      string // substring of the expected violation; empty means admitted
	}{
		{
			name: "ordinary pod",
		},
		{
			name:      "the plugin's own inventory socket mount",
			pod:       injectedPod,
			ctr:       injectedSocketMount,
			ownSocket: "/var/run/nri-image-policy",
		},
		{
			name:      "the node's own CDS policy mount",
			pod:       injectedPod,
			ctr:       injectedPinsMount,
			ownSocket: "/var/run/nri-image-policy",
			ownPins:   "/run/c8s-node/cds.json",
		},
		{
			name: "a CDS policy mount from a source the plugin does not own",
			pod:  injectedPod,
			ctr: func(c *api.Container) {
				injectedPinsMount(c)
				c.Mounts[len(c.Mounts)-1].Source = "/tmp/attacker-pins.json"
			},
			ownSocket: "/var/run/nri-image-policy",
			ownPins:   "/run/c8s-node/cds.json",
			want:      "host path bind mount",
		},
		{
			name: "a writable mount of the node's CDS policy",
			pod:  injectedPod,
			ctr: func(c *api.Container) {
				injectedPinsMount(c)
				c.Mounts[len(c.Mounts)-1].Options = []string{"rbind", "rw"}
			},
			ownSocket: "/var/run/nri-image-policy",
			ownPins:   "/run/c8s-node/cds.json",
			want:      "host path bind mount",
		},
		{
			name: "the CDS policy mount in a container the webhook did not inject",
			pod:  injectedPod,
			ctr: func(c *api.Container) {
				injectedPinsMount(c)
				c.Name = "app"
			},
			ownSocket: "/var/run/nri-image-policy",
			ownPins:   "/run/c8s-node/cds.json",
			want:      "host path bind mount",
		},
		{
			name: "a writable mount of the socket directory",
			pod:  injectedPod,
			ctr: func(c *api.Container) {
				injectedSocketMount(c)
				c.Mounts[len(c.Mounts)-1].Options = []string{"rbind", "rw"}
			},
			ownSocket: "/var/run/nri-image-policy",
			want:      "host path bind mount",
		},
		{
			name: "the socket mount in a container the webhook did not inject",
			pod:  injectedPod,
			ctr: func(c *api.Container) {
				injectedSocketMount(c)
				c.Name = "app"
			},
			ownSocket: "/var/run/nri-image-policy",
			want:      "host path bind mount",
		},
		{
			name:      "the socket mount in a pod without the injection annotation",
			ctr:       injectedSocketMount,
			ownSocket: "/var/run/nri-image-policy",
			want:      "host path bind mount",
		},
		{
			name: "a socket mount the plugin did not inject",
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{
					Destination: "/elsewhere",
					Type:        "bind",
					Source:      "/var/run/nri-image-policy",
				})
			},
			ownSocket: "/var/run/nri-image-policy",
			want:      "host path bind mount",
		},
		{
			name: "host network",
			pod: func(p *api.PodSandbox) {
				p.Linux.Namespaces = slices.DeleteFunc(p.Linux.Namespaces,
					func(ns *api.LinuxNamespace) bool { return ns.Type == "network" || ns.Type == "uts" })
			},
			want: "host network namespace",
		},
		{
			name: "host pid",
			pod: func(p *api.PodSandbox) {
				p.Linux.Namespaces = slices.DeleteFunc(p.Linux.Namespaces,
					func(ns *api.LinuxNamespace) bool { return ns.Type == "pid" })
			},
			want: "host pid namespace",
		},
		{
			name: "host ipc",
			pod: func(p *api.PodSandbox) {
				p.Linux.Namespaces = slices.DeleteFunc(p.Linux.Namespaces,
					func(ns *api.LinuxNamespace) bool { return ns.Type == "ipc" })
			},
			want: "host ipc namespace",
		},
		{
			name: "no sandbox spec",
			pod:  func(p *api.PodSandbox) { p.Linux = nil },
			want: "host ipc namespace",
		},
		{
			name: "privileged: no cgroup namespace",
			ctr: func(c *api.Container) {
				c.Linux.Namespaces = slices.DeleteFunc(c.Linux.Namespaces,
					func(ns *api.LinuxNamespace) bool { return ns.Type == "cgroup" })
			},
			want: "no cgroup namespace",
		},
		{
			name: "privileged: writable sysfs",
			ctr: func(c *api.Container) {
				c.Mounts[1].Options = []string{"nosuid", "noexec", "nodev", "rw"}
			},
			want: "writable sysfs or cgroupfs",
		},
		{
			name: "privileged: host devices",
			ctr: func(c *api.Container) {
				c.Linux.Devices = []*api.LinuxDevice{{Path: "/dev/sda", Type: "b"}}
			},
			want: "host device node",
		},
		{
			name: "hostPath bind",
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{Destination: "/host", Type: "bind", Source: "/"})
			},
			want: "host path bind mount",
		},
		{
			name: "another pod's kubelet directory",
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{
					Destination: "/steal",
					Type:        "bind",
					Source:      "/var/lib/kubelet/pods/99999999-0000-0000-0000-000000000000/volumes/x",
				})
			},
			want: "host path bind mount",
		},
		{
			name: "own kubelet directory escaped with ..",
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{
					Destination: "/host",
					Type:        "bind",
					Source:      "/var/lib/kubelet/pods/" + testPodUID + "/../../../..",
				})
			},
			want: "host path bind mount",
		},
		{
			name: "own sandbox directory escaped with ..",
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{
					Destination: "/sandboxes",
					Type:        "bind",
					Source:      "/run/k3s/containerd/io.containerd.grpc.v1.cri/sandboxes/" + testSandboxID + "/..",
				})
			},
			want: "host path bind mount",
		},
		{
			name: "pod UID as a segment outside the kubelet root",
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{Destination: "/mnt", Type: "bind", Source: "/mnt/" + testPodUID + "/data"})
			},
			want: "host path bind mount",
		},
		{
			name: "control-plane-chosen UID naming a host directory",
			pod:  func(p *api.PodSandbox) { p.Uid = "etc" },
			ctr: func(c *api.Container) {
				c.Mounts = append(c.Mounts, &api.Mount{Destination: "/host-etc", Type: "bind", Source: "/etc"})
			},
			want: "host path bind mount",
		},
		{
			name: "unidentifiable pod",
			pod: func(p *api.PodSandbox) {
				p.Uid, p.Id = "", ""
			},
			want: "host path bind mount",
		},
		{
			name: "CDI injection",
			ctr:  func(c *api.Container) { c.CDIDevices = []*api.CDIDevice{{Name: "nvidia.com/gpu=0"}} },
			want: "CDI device injection",
		},
		{
			name: "OCI hook",
			ctr: func(c *api.Container) {
				c.Hooks = &api.Hooks{CreateRuntime: []*api.Hook{{Path: "/usr/bin/evil"}}}
			},
			want: "OCI hook",
		},
		{
			name: "host network device",
			ctr: func(c *api.Container) {
				c.Linux.NetDevices = map[string]*api.LinuxNetDevice{"eth0": {}}
			},
			want: "host network device",
		},
		{
			name: "container sysctl",
			ctr:  func(c *api.Container) { c.Linux.Sysctl = map[string]string{"kernel.shm_rmid_forced": "0"} },
			want: "container sysctl",
		},
		{
			name: "no container spec",
			ctr:  func(c *api.Container) { c.Linux = nil },
			want: "no cgroup namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod, ctr := sandboxedPod(), sandboxedContainer()
			if tt.pod != nil {
				tt.pod(pod)
			}
			if tt.ctr != nil {
				tt.ctr(ctr)
			}
			own := nodeMounts{
				socketDir: tt.ownSocket,
				cdsPins:   tt.ownPins,
			}
			got := observeSandbox(pod, ctr, own).violations()
			if tt.want == "" {
				if len(got) != 0 {
					t.Fatalf("observeSandbox(ordinary pod).violations() = %v, want none", got)
				}
				return
			}
			if !slices.ContainsFunc(got, func(v string) bool { return strings.Contains(v, tt.want) }) {
				t.Fatalf("observeSandbox(%s).violations() = %v, want one containing %q", tt.name, got, tt.want)
			}
		})
	}
}

// privilegedContainer is a container carrying one violation, used to drive the
// plugin-level modes.
func privilegedContainer() *api.Container {
	ctr := sandboxedContainer()
	ctr.Mounts = append(ctr.Mounts, &api.Mount{Destination: "/host", Type: "bind", Source: "/"})
	ctr.Annotations = map[string]string{annotationImageName: testFloorImage}
	return ctr
}

// tcbAllowlist is a base holding one entry for digest: argv pinned to
// /floor when pinned, otherwise any, and mounts unconstrained — the shape the
// node image's generated system entries have.
func tcbAllowlist(digest string, pinned bool) *allowlist.Allowlist {
	command := allowlist.ArgvPolicy{Policy: allowlist.PolicyAny}
	args := allowlist.ArgvPolicy{Policy: allowlist.PolicyAny}
	if pinned {
		command = allowlist.ArgvPolicy{Policy: allowlist.PolicyExact, Argv: []string{"/floor"}}
		args = allowlist.ArgvPolicy{Policy: allowlist.PolicyExact}
	}
	return &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{
		"floor": {Label: "floor", Containers: []allowlist.Container{{
			Digest:  mustDigestOrPanic(digest),
			Image:   "floor",
			Command: command,
			Args:    args,
			Mounts:  allowlist.MountPolicy{Policy: allowlist.PolicyAny},
		}}},
	}}
}

func TestCheckSandboxModes(t *testing.T) {
	tests := []struct {
		name        string
		sandbox     sandboxMode
		nodeTCB     bool
		floorDigest string // digest in the base allowlist; empty means the base holds another image
		pinned      bool   // the base entry pins argv to /floor
		argv        []string
		want        imageVerdict
	}{
		{name: "off is not observed", sandbox: SandboxOff, want: verdictAllow},
		{name: "audit admits", sandbox: SandboxAudit, want: verdictAllow},
		{name: "enforce denies", sandbox: SandboxEnforce, want: verdictDeny},
		{
			name: "floor entry is denied without the node-TCB marker", sandbox: SandboxEnforce,
			floorDigest: pushDigestA, want: verdictDeny,
		},
		{
			name: "node TCB exempts a floor entry", sandbox: SandboxEnforce, nodeTCB: true,
			floorDigest: pushDigestA, want: verdictAllow,
		},
		{
			name: "node TCB does not exempt a served entry", sandbox: SandboxEnforce, nodeTCB: true,
			floorDigest: pushDigestB, want: verdictDeny,
		},
		{
			name: "node TCB exempts a pinned entry at its own argv", sandbox: SandboxEnforce, nodeTCB: true,
			floorDigest: pushDigestA, pinned: true, argv: []string{"/floor"}, want: verdictAllow,
		},
		{
			name: "node TCB does not exempt a pinned entry restaged with a shell", sandbox: SandboxEnforce, nodeTCB: true,
			floorDigest: pushDigestA, pinned: true, argv: []string{"/bin/sh", "-c", "id"}, want: verdictDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			floor := tcbAllowlist(pushDigestB, false)
			if tt.floorDigest != "" {
				floor = tcbAllowlist(tt.floorDigest, tt.pinned)
			}
			cfg := &config{
				Allowlist: allowlistConfig{Base: floor, NodeTCB: tt.nodeTCB},
				Policy:    policyConfig{Mode: ModeFailClosed, Sandbox: tt.sandbox},
			}
			p := newTestPlugin(cfg)
			p.policy = newPolicyStore(floor)

			pod, ctr := sandboxedPod(), privilegedContainer()
			ctr.Args = tt.argv
			verdict := verdictAllow
			reason := ""
			if cfg.sandboxObserved() {
				mounts := newMountObserver(nil).Observe(pod, ctr)
				verdict, reason = p.checkSandbox(context.Background(), cfg, pod, ctr, testFloorImage, containerEnv(ctr), mounts)
			}
			if verdict != tt.want {
				t.Fatalf("checkSandbox(%s) = %d %q, want %d", tt.name, verdict, reason, tt.want)
			}
			if tt.want == verdictDeny && !strings.Contains(reason, "host path bind mount") {
				t.Fatalf("checkSandbox(%s) reason = %q, want it to name the violation", tt.name, reason)
			}
		})
	}
}

func TestSandboxConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
		want    sandboxMode // expected effective policy.sandbox
	}{
		{
			name: "defaults to enforce",
			yaml: "allowlist:" + baseYAML(pushDigestA, "img"),
			want: SandboxEnforce,
		},
		{
			name: "explicit audit",
			yaml: "allowlist:" + baseYAML(pushDigestA, "img") + "policy:\n  sandbox: audit\n",
			want: SandboxAudit,
		},
		{
			name:    "unknown mode",
			yaml:    "allowlist:" + baseYAML(pushDigestA, "img") + "policy:\n  sandbox: yes-please\n",
			wantErr: "policy.sandbox must be",
		},
		{
			name:    "node_tcb needs a floor",
			yaml:    "allowlist:\n  node_tcb: true\npolicy:\n  label_rules:\n    - name: r\n      match_expressions:\n        - key: k\n          operator: Exists\n",
			wantErr: "allowlist.node_tcb needs a non-empty allowlist.base",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig([]byte(tt.yaml))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseConfig() error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseConfig() = %v, want no error", err)
			}
			if cfg.sandboxMode() != tt.want {
				t.Fatalf("sandboxMode() = %q, want %q", cfg.sandboxMode(), tt.want)
			}
		})
	}
}

// The sandbox policy reads the whole container spec, so it must run on the
// persisted one — the final phase — and not at CreateContainer, which precedes
// the other plugins' adjustments.
func TestSandboxRunsOnlyInTheFinalPhase(t *testing.T) {
	tests := []struct {
		name  string
		phase launchPhase
		want  imageVerdict
	}{
		{name: "create phase admits", phase: launchPreliminary, want: verdictAllow},
		{name: "final phase denies", phase: launchFinal, want: verdictDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{
				Allowlist: allowlistConfig{Base: anyAllowlist(map[string]string{pushDigestA: "floor"})},
				Policy:    policyConfig{Mode: ModeFailClosed, Sandbox: SandboxEnforce},
			}
			p, _ := newCachedPlugin(cfg, &allowlist.Allowlist{})
			verdict, reason := p.checkContainerPhase(context.Background(), cfg,
				sandboxedPod(), privilegedContainer(), testFloorImage, tt.phase)
			if verdict != tt.want {
				t.Fatalf("checkContainerPhase(phase=%d) = %d %q, want %d", tt.phase, verdict, reason, tt.want)
			}
		})
	}
}

// A sandbox denial is not downgraded in an exempt namespace, even when the
// digest is in the frozen snapshot: the snapshot admits an image, not host
// privilege.
func TestSandboxDenialIsNotNamespaceExempt(t *testing.T) {
	p := exemptPlugin(t, filepath.Join(t.TempDir(), "snap.json"), "kube-system")
	snap := newExemptSnapshot([]string{"kube-system"})
	snap.add("kube-system", pushDigestA)
	p.exempt.Store(snap)
	p.cfg.Policy.Sandbox = SandboxEnforce

	pod := sandboxedPod()
	pod.Namespace = "kube-system"
	verdict, reason := p.checkContainer(context.Background(), p.cfg, pod, privilegedContainer(), testFloorImage)
	if verdict != verdictDeny || !strings.Contains(reason, "host path bind mount") {
		t.Fatalf("checkContainer(exempt namespace, privileged) = %d %q, want deny naming the violation", verdict, reason)
	}
}
