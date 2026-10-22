//go:build linux

package nriimagepolicy

import (
	"context"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// AdmitPodRoleInTheNamespace tests production admission from rendered policy
// with a fake containerd client and real namespaces, without TEE hardware.
func AdmitPodRoleInTheNamespace(t *testing.T, cfg *config) {
	t.Helper()
	if cfg.Mesh == nil || !cfg.Mesh.Isolated {
		t.Fatal("pod-role config requires isolation")
	}
	for _, namespace := range []string{"tenant", "kube-system"} {
		t.Run(namespace, func(t *testing.T) { admitPodRoleInTheNamespace(t, cfg, namespace) })
	}
}

func admitPodRoleInTheNamespace(t *testing.T, cfg *config, namespace string) {
	t.Helper()
	pid := sandboxProcess(t)
	pod := sandboxedPod()
	pod.Namespace = namespace
	pod.Pid = pid
	for _, ns := range pod.Linux.Namespaces {
		if ns.Type == "network" {
			ns.Path = sandboxNetNSPath(pid)
		}
	}
	p := newTestPlugin(cfg)
	p.mesh = newMeshGate(cfg.Mesh, discardLogger())
	if err := p.prepareCDSAddress(); err != nil {
		t.Fatalf("prepare standalone inventory: %v", err)
	}
	if err := p.RunPodSandbox(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	ctr := sandboxedContainer()
	ctr.PodSandboxId = pod.GetId()
	ctr.Mounts = nil
	ctr.Args = []string{"/app"}
	ctr.Linux.Namespaces = append(ctr.Linux.Namespaces, &api.LinuxNamespace{Type: pidNamespace})
	ctr.User = &api.User{Uid: testWorkloadUID}
	ctr.Annotations = map[string]string{annotationImageName: "registry/repo@sha256:" + strings.Repeat("b", 64)}
	validate := func() error {
		return p.ValidateContainerAdjustment(context.Background(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr})
	}
	ctr.Name = "init"
	if err := validate(); err != nil {
		t.Fatalf("signed nonroot init container requires no mesh endpoint: %v", err)
	}
	ctr.Name = "app"
	if err := validate(); err != nil {
		t.Fatalf("signed application after init container: %v", err)
	}
	ctr.Annotations[annotationImageName] = "registry/repo@sha256:" + strings.Repeat("a", 64)
	if err := validate(); err == nil {
		t.Fatal("unsigned workload admitted")
	}
	delete(ctr.Annotations, annotationImageName)
	if err := validate(); err == nil {
		t.Fatal("workload without image evidence admitted")
	}
	ctr.Annotations[annotationImageName] = "registry/repo@sha256:" + strings.Repeat("b", 64)
	if err := validate(); err != nil {
		t.Fatalf("signed workload retry: %v", err)
	}
	ctr.Annotations[cdiAnnotationPrefix+"device"] = "vendor/device=socket"
	if err := validate(); err == nil || !strings.Contains(err.Error(), "CDI device injection") {
		t.Fatalf("annotated CDI was admitted: %v", err)
	}
	delete(ctr.Annotations, cdiAnnotationPrefix+"device")
	p.inventory = newAdmissionInventory(t.TempDir())
	injectedPod(pod)
	ctr.User.Gid = 65532
	for _, name := range []string{workloadclaims.CertContainerName, workloadclaims.AttestContainerName} {
		ctr.Name = name
		adjust, _, err := p.CreateContainer(context.Background(), pod, ctr)
		if err != nil || len(adjust.GetMounts()) != 0 {
			t.Fatalf("isolated create %s: adjustment=%v error=%v", name, adjust, err)
		}
		req := &api.ValidateContainerAdjustmentRequest{
			Pod:       pod,
			Container: ctr,
			Adjust: &api.ContainerAdjustment{Mounts: []*api.Mount{
				readOnlyBind(cfg.WorkloadClaims.SocketDir, workloadclaims.SidecarSocketDir),
			}},
		}
		if err := p.ValidateContainerAdjustment(context.Background(), req); err == nil {
			t.Fatalf("forged %s consumer reached host sockets", name)
		}
		req.Adjust.CDIDevices = []*api.CDIDevice{{Name: "vendor/device=socket"}}
		if err := p.ValidateContainerAdjustment(context.Background(), req); err == nil || !strings.Contains(err.Error(), "CDI device injection") {
			t.Fatalf("deferred CDI hid the %s socket mount: %v", name, err)
		}
	}
	p.mesh.noteMeshStarted(pod.GetId())
	if err := p.mesh.verifyMember(pod.GetId()); err == nil {
		t.Fatal("isolated pod obtained a mesh assertion")
	}
	if err := unix.Kill(int(pid), unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if err := waitForNamespaceGone(sandboxNetNSPath(pid)); err != nil {
		t.Fatal(err)
	}
	if err := validate(); err == nil {
		t.Fatal("workload admitted after its protected namespace disappeared")
	}
}
