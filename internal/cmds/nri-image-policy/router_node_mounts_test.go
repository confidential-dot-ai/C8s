package nriimagepolicy

import (
	"os/exec"
	"slices"
	"testing"

	"github.com/containerd/nri/pkg/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestChartRouterNodeMountAdmission(t *testing.T) {
	deployment := renderBakedRouterDeployment(t)
	for _, client := range []struct {
		name string
		role string
	}{
		{
			name: workloadclaims.AttestContainerName,
			role: upstreamRole,
		},
		{
			name: "allowlist-proxy",
			role: CredentialRole,
		},
	} {
		t.Run(client.name, func(t *testing.T) {
			p := routerNodeMountPlugin(t)
			p.mountStorage = fixedStorage(allowlist.MountMemory)
			pod := meshPod(deployment.Namespace, deployment.Name, testNetNS)
			pod.Uid = "5a1d-pod"
			pod.Annotations = deployment.Spec.Template.Annotations
			ctr := chartRouterContainer(t, pod, deployment.Spec.Template.Spec, client.name)
			adjustment, _, err := p.CreateContainer(t.Context(), pod, ctr)
			if err != nil {
				t.Fatalf("create chart container: %v", err)
			}
			request := &api.ValidateContainerAdjustmentRequest{
				Pod:       pod,
				Container: ctr,
				Adjust:    adjustment,
			}
			if err := p.ValidateContainerAdjustment(t.Context(), request); err != nil {
				t.Fatalf("validate chart container: %v", err)
			}
			final, _ := adjustedLaunchContainer(request)
			mounts := p.adjustedMounts(request, final)
			if err := p.StartContainer(t.Context(), pod, final); err != nil {
				t.Fatalf("start chart container: %v", err)
			}
			launch := p.observedLaunch(t.Context(), final, final.Annotations[annotationImageName], containerEnv(final), mounts)
			if role := p.roleOf(launch); role != client.role {
				t.Fatalf("final measured role = %q, want %q", role, client.role)
			}
			assertRouterMeshRole(t, p, pod, final, launch)
			_, containers, _, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || len(containers) != 1 || containers[0].Role != client.role {
				t.Fatalf("inventory = %v, %v; want role %s", containers, err, client.role)
			}
			if client.role == CredentialRole {
				socket := onlyMountAt(t, containers[0].Mounts, workloadclaims.SidecarSocketDir)
				if socket.Class != allowlist.MountHost {
					t.Fatalf("router socket bypassed its exact host mount rule: %+v", socket)
				}
			}
		})
	}
}

func TestRouterNodePolicyMountsRefuseForeignAndWritableSources(t *testing.T) {
	for _, destination := range []string{workloadclaims.CDSPinsPath, workloadclaims.CDSAddressPath} {
		for _, change := range []string{"foreign source", "writable", "wrong identity"} {
			t.Run(destination+"/"+change, func(t *testing.T) {
				p := routerNodeMountPlugin(t)
				pod := routerNodeMountPod()
				declaration := p.cfg.Allowlist.Base.Workloads["c8s-allowlist-proxy"].Containers[0]
				ctr := routerNodeMountContainer(pod, "allowlist-proxy", workloadclaims.CredentialsUID, declaration)
				adjustment := mustCredentialMounts(t, p, pod, ctr)
				mount := mountTo(adjustment, destination)
				switch change {
				case "foreign source":
					mount.Source = "/other-node/policy"
				case "writable":
					mount.Options = append(mount.Options, "rw")
				case "wrong identity":
					ctr.User.Uid = testWorkloadUID
				}
				request := &api.ValidateContainerAdjustmentRequest{
					Pod:       pod,
					Container: ctr,
					Adjust:    adjustment,
				}
				if err := p.ValidateContainerAdjustment(t.Context(), request); err == nil {
					t.Fatal("unsafe router credential adjustment admitted")
				}
				final, _ := adjustedLaunchContainer(request)
				mounts := p.adjustedMounts(request, final)
				selected := onlyMountAt(t, mounts, destination)
				if selected.Class != allowlist.MountHost {
					t.Fatalf("unsafe policy mount received platform classification: %+v", selected)
				}
				if err := p.StartContainer(t.Context(), pod, final); err == nil {
					t.Fatal("unsafe router credential launch admitted")
				}
			})
		}
	}
}

func TestRouterNodeMountEligibilityDoesNotAuthorizeLaunch(t *testing.T) {
	for _, client := range []struct {
		name     string
		workload string
		uid      uint32
	}{
		{
			name:     workloadclaims.AttestContainerName,
			workload: "c8s-router-upstream",
			uid:      workloadclaims.UpstreamUID,
		},
		{
			name:     "allowlist-proxy",
			workload: "c8s-allowlist-proxy",
			uid:      workloadclaims.CredentialsUID,
		},
	} {
		for _, change := range []string{"unapproved command", "unapproved image"} {
			t.Run(client.name+"/"+change, func(t *testing.T) {
				p := routerNodeMountPlugin(t)
				pod := routerNodeMountPod()
				declaration := p.cfg.Allowlist.Base.Workloads[client.workload].Containers[0]
				ctr := routerNodeMountContainer(pod, client.name, client.uid, declaration)
				adjustment := mustCredentialMounts(t, p, pod, ctr)
				ctr.Mounts = append(ctr.Mounts, adjustment.GetMounts()...)
				if change == "unapproved command" {
					ctr.Args = []string{"/unapproved"}
				} else {
					ctr.Annotations[annotationImageName] = "registry/unapproved@" + pushDigestB
				}
				if _, _, err := p.CreateContainer(t.Context(), pod, ctr); err == nil {
					t.Fatal("node mount eligibility admitted unapproved launch at creation")
				}
				mounts := routerNodeMountObserver(p).Observe(pod, ctr)
				address := onlyMountAt(t, mounts, workloadclaims.CDSAddressPath)
				if address.Class != allowlist.MountPlatform {
					t.Fatalf("matching node client did not retain platform address classification: %+v", address)
				}
				verdict, reason := p.checkContainerObserved(t.Context(), p.cfg, pod, ctr, ctr.Annotations[annotationImageName], launchFinal, containerEnv(ctr), mounts)
				if verdict != verdictDeny {
					t.Fatalf("unapproved final launch admission = %v: %s", verdict, reason)
				}
			})
		}
	}
}

func onlyMountAt(t *testing.T, mounts []allowlist.ObservedMount, destination string) allowlist.ObservedMount {
	t.Helper()
	var matches []allowlist.ObservedMount
	for _, mount := range mounts {
		if mount.Destination == destination {
			matches = append(matches, mount)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("observed %d mounts at %s, want exactly one: %+v", len(matches), destination, matches)
	}
	return matches[0]
}

func routerNodeMountPlugin(t *testing.T) *plugin {
	t.Helper()
	cfg, err := parseConfig([]byte(renderNodeImagePolicy(t)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.WorkloadClaims.AdvertiseHost = "10.0.0.1"
	cfg.WorkloadClaims.CDSNodePort = 30808
	if err := bindCredentialRole(cfg); err != nil {
		t.Fatal(err)
	}
	p := newTestPlugin(cfg)
	p.SetReady()
	p.cdsPins = "/run/node-cds-policy.json"
	p.cdsAddress = "/run/node-cds-address"
	p.inventory = newAdmissionInventory(t.TempDir())
	return p
}

func routerNodeMountPod() *api.PodSandbox {
	return &api.PodSandbox{
		Id:        "router-sandbox",
		Uid:       "5a1d-pod",
		Name:      "router",
		Namespace: routerNamespace,
	}
}

func routerNodeMountContainer(pod *api.PodSandbox, name string, uid uint32, declaration allowlist.Container) *api.Container {
	ctr := makeCtrWithImageArgs(pod.Id, name, declaration.Image, slices.Clone(declaration.Command.Argv))
	ctr.User = &api.User{Uid: uid}
	for _, rule := range declaration.Mounts.Rules {
		source := rule.Source
		switch rule.Kind {
		case allowlist.MountEmptyDir:
			source = podVolumeSource(rule.Source)
		case allowlist.MountData:
			source = kubeletRoot + "/pods/" + pod.Uid + "/volumes/kubernetes.io~secret/" + rule.Source
		}
		ctr.Mounts = append(ctr.Mounts, readOnlyBind(source, rule.Destination))
	}
	return ctr
}

func routerNodeMountObserver(p *plugin) mountObserver {
	return newMountObserver(fixedStorage(allowlist.MountMemory), nodeMounts{
		socketDir:  p.cfg.WorkloadClaims.SocketDir,
		cdsPins:    p.cdsPins,
		cdsAddress: p.cdsAddress,
	})
}

func renderBakedRouterDeployment(t *testing.T) appsv1.Deployment {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	cmd := exec.Command("helm", "template", "c8s", "../../helmchart/c8s",
		"--show-only", "templates/router-deployment.yaml",
		"--namespace", "c8s-system", "--kube-version", "1.30.0",
		"--set", "node.baked=true,attestationApi.enabled=false,nriImagePolicy.enabled=false,nriImagePolicy.bootstrapAllowlist.deriveComponents=true,router.attest.enabled=true",
		"--set-string", "image.digest="+operatorImageDigest,
		"--set-string", "armtlsMesh.image.digest="+meshImageDigest,
		"--set-string", "router.nginx.image.digest="+routerImageDigest,
		"--set-string", "cds.image.digest="+pushDigestA,
		"--set-string", "nriImagePolicy.mesh.resolver=10.43.0.10",
		"--set-string", "nriImagePolicy.mesh.clusterRanges[0]=10.42.0.0/16",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("render baked router: %v\n%s", err, out)
	}
	var deployment appsv1.Deployment
	if err := sigsyaml.UnmarshalStrict(out, &deployment); err != nil {
		t.Fatal(err)
	}
	if deployment.Kind != "Deployment" || deployment.Name != "c8s-router" {
		t.Fatalf("unexpected chart workload: %s %s", deployment.Kind, deployment.Name)
	}
	return deployment
}

func chartRouterContainer(t *testing.T, pod *api.PodSandbox, spec corev1.PodSpec, name string) *api.Container {
	t.Helper()
	if spec.HostPID || (spec.ShareProcessNamespace != nil && *spec.ShareProcessNamespace) {
		t.Fatal("chart router must give each container a private PID namespace")
	}
	i := slices.IndexFunc(spec.Containers, func(c corev1.Container) bool {
		return c.Name == name
	})
	if i < 0 {
		t.Fatalf("chart router has no %s container", name)
	}
	c := spec.Containers[i]
	if c.SecurityContext == nil || c.SecurityContext.RunAsUser == nil || c.SecurityContext.RunAsGroup == nil {
		t.Fatalf("chart router %s requires an explicit uid and gid", name)
	}
	ctr := makeCtrWithImageArgs(pod.Id, c.Name, c.Image, slices.Concat(c.Command, c.Args))
	ctr.User = &api.User{
		Uid: uint32(*c.SecurityContext.RunAsUser),
		Gid: uint32(*c.SecurityContext.RunAsGroup),
	}
	ctr.Linux = &api.LinuxContainer{
		Namespaces: []*api.LinuxNamespace{{Type: pidNamespace}},
	}
	for _, env := range c.Env {
		if env.ValueFrom != nil {
			t.Fatalf("unresolved chart environment %s", env.Name)
		}
		ctr.Env = append(ctr.Env, env.Name+"="+env.Value)
	}
	for _, mount := range c.VolumeMounts {
		if mount.SubPath != "" || mount.SubPathExpr != "" {
			t.Fatalf("unsupported chart subpath mount: %+v", mount)
		}
		i := slices.IndexFunc(spec.Volumes, func(v corev1.Volume) bool {
			return v.Name == mount.Name
		})
		if i < 0 {
			t.Fatalf("missing chart volume %s", mount.Name)
		}
		volume := spec.Volumes[i]
		source := ""
		switch {
		case volume.HostPath != nil:
			source = volume.HostPath.Path
		case volume.EmptyDir != nil && volume.EmptyDir.Medium == corev1.StorageMediumMemory:
			source = kubeletRoot + "/pods/" + pod.Uid + "/volumes/" + emptyDirPlugin + "/" + volume.Name
		default:
			t.Fatalf("unsupported chart volume: %+v", volume)
		}
		bind := readOnlyBind(source, mount.MountPath)
		if !mount.ReadOnly {
			bind.Options = append(bind.Options, "rw")
		}
		ctr.Mounts = append(ctr.Mounts, bind)
	}
	return ctr
}

func assertRouterMeshRole(t *testing.T, p *plugin, pod *api.PodSandbox, ctr *api.Container, launch allowlist.RunningContainer) {
	t.Helper()
	gate, state := gateWithPod(pod)
	gate.policy = p.cfg.Mesh
	state.meshStarted = true
	role := p.roleOf(launch)
	_, _, err := gate.admissible(pod, ctr, gatedContainer{
		role:         role,
		mountsPinned: p.bindsRoleMounts(launch, role),
		digest:       launch.Digest,
		argv:         launch.Argv,
	})
	if err != nil {
		t.Fatalf("chart container mesh role admission: %v", err)
	}
}
