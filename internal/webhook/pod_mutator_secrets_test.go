package webhook

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

func secretsConfig() Config {
	return Config{
		GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
		CDSURL:            "https://cds.c8s-system.svc:8443",
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		CertDir:           "/etc/c8s/certs",
	}
}

func podWithApp() *corev1.Pod {
	return &corev1.Pod{
		Name: "api", Namespace: "tenant",
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
}

func mutateWithSecrets(t *testing.T, pod *corev1.Pod, specs []string, dir string) {
	t.Helper()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: specs, Dir: dir},
	}, secretsConfig())
}

func containerNamed(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return &pod.Spec.InitContainers[i]
		}
	}
	return nil
}

// No annotation, no fetcher: a pod that asks for nothing gets the cert
// containers only.
func TestNoSecretsRequestedInjectsNothing(t *testing.T) {
	pod := podWithApp()
	mutateWithSecrets(t, pod, nil, "")
	if c := containerNamed(pod, reservedSecretContainerName); c != nil {
		t.Fatal("the fetcher was injected without a secrets annotation")
	}
	for _, v := range pod.Spec.Volumes {
		if v.Name == secretsVolumeName {
			t.Fatal("the secrets volume was injected without a secrets annotation")
		}
	}
}

// The fetcher must run alongside the workload, not before it: CDS releases only
// once every main container is running, so an ordinary init container would
// deadlock the pod it gates.
func TestFetcherIsANativeSidecarOrderedAfterCertWait(t *testing.T) {
	pod := podWithApp()
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

	names := make([]string, 0, len(pod.Spec.InitContainers))
	for _, c := range pod.Spec.InitContainers {
		names = append(names, c.Name)
	}
	want := []string{reservedCertContainerName, reservedCertWaitContainerName, reservedSecretContainerName}
	if !slices.Equal(names[:3], want) {
		t.Fatalf("init containers = %v, want %v first", names, want)
	}

	fetcher := containerNamed(pod, reservedSecretContainerName)
	if fetcher.RestartPolicy == nil || *fetcher.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatal("the fetcher is not a native sidecar; exiting would restart it for the pod's life")
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("main containers = %d, want the workload's own only", len(pod.Spec.Containers))
	}
}

func TestFetcherArgs(t *testing.T) {
	pod := podWithApp()
	mutatePod(pod, &injection{
		WorkloadID: "api",
		Secrets:    secretsSpec{Specs: []string{"DB=/api/db", "HF=/api/hf"}},
	}, secretsConfig())

	args := strings.Join(containerNamed(pod, reservedSecretContainerName).Args, " ")
	for _, want := range []string{
		"get-secret",
		"--cds-url=https://cds.c8s-system.svc:8443",
		"--secret=DB=/api/db",
		"--secret=HF=/api/hf",
		"--out-dir=" + defaultSecretDir,
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("args %q missing %q", args, want)
		}
	}
}

func TestSecretDirOverride(t *testing.T) {
	pod := podWithApp()
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "/var/run/app-secrets")

	fetcher := containerNamed(pod, reservedSecretContainerName)
	if !strings.Contains(strings.Join(fetcher.Args, " "), "--out-dir=/var/run/app-secrets") {
		t.Fatalf("args = %v, want the overridden dir", fetcher.Args)
	}
	for _, c := range pod.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.Name == secretsVolumeName && m.MountPath != "/var/run/app-secrets" {
				t.Fatalf("workload mount path = %q, want the overridden dir", m.MountPath)
			}
		}
	}
}

// The directory is readable pod-wide by design, but only the fetcher may write
// it: a workload able to write could replace a value a sibling has yet to read.
func TestOnlyTheFetcherMountsSecretsWritable(t *testing.T) {
	pod := podWithApp()
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{Name: "user-init"})
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

	check := func(c corev1.Container) {
		for _, m := range c.VolumeMounts {
			if m.Name != secretsVolumeName {
				continue
			}
			wantRO := c.Name != reservedSecretContainerName
			if m.ReadOnly != wantRO {
				t.Fatalf("container %q mounts secrets ReadOnly=%v, want %v", c.Name, m.ReadOnly, wantRO)
			}
		}
	}
	for _, c := range pod.Spec.Containers {
		check(c)
	}
	for _, c := range pod.Spec.InitContainers {
		check(c)
	}
}

// A hostPath here would write a released secret to host-visible storage,
// outside the TEE boundary.
func TestReservedSecretsVolumeMustBeMemoryBacked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source corev1.VolumeSource
		wantOK bool
	}{
		{"memory emptyDir", corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}, true},
		{"hostPath", corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/exfil"}}, false},
		{"disk emptyDir", corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}, false},
		{"pvc", corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			pod.Spec.Volumes = []corev1.Volume{{Name: secretsVolumeName, VolumeSource: tc.source}}
			err := rejectReservedSecretsVolume(pod)
			if tc.wantOK && err != nil {
				t.Fatalf("rejected a valid volume: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("accepted a volume that would leave the TEE boundary")
			}
		})
	}
}

// The injected volume is memory-backed: a released value must never reach the
// node's disk.
func TestInjectedSecretsVolumeIsTmpfs(t *testing.T) {
	pod := podWithApp()
	mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")

	var found *corev1.Volume
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == secretsVolumeName {
			found = &pod.Spec.Volumes[i]
		}
	}
	if found == nil {
		t.Fatal("no secrets volume was injected")
	}
	if found.EmptyDir == nil || found.EmptyDir.Medium != corev1.StorageMediumMemory {
		t.Fatalf("volume = %+v, want a memory-backed emptyDir", found.VolumeSource)
	}
}

// A pod declaring the fetcher's name would collide with the injected one.
func TestFetcherNameIsReserved(t *testing.T) {
	pod := podWithApp()
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: reservedSecretContainerName})
	if err := rejectReservedCertContainer(pod); err == nil {
		t.Fatal("a pod claiming the fetcher's container name was accepted")
	}
}

// The secrets annotations are injection detail, so setting one without opting
// the pod in must fail loudly rather than be ignored.
func TestSecretsAnnotationsRequireOptIn(t *testing.T) {
	for _, name := range []string{AnnotationSecrets, AnnotationSecretDir} {
		pod := podWithApp()
		pod.Annotations = map[string]string{name: "DB=/api/db"}
		if _, err := parseAnnotations(pod, ""); err == nil {
			t.Fatalf("%s without %s was silently ignored", name, AnnotationWorkload)
		}
	}
}

func TestSecretsAnnotationParsing(t *testing.T) {
	pod := podWithApp()
	pod.Annotations = map[string]string{
		AnnotationWorkload:  "api",
		AnnotationSecrets:   " DB=/api/db , HF=/api/hf ",
		AnnotationSecretDir: "/var/run/app-secrets",
	}
	inj, err := parseAnnotations(pod, "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inj.Secrets.Specs, []string{"DB=/api/db", "HF=/api/hf"}) {
		t.Fatalf("specs = %v", inj.Secrets.Specs)
	}
	if inj.Secrets.Dir != "/var/run/app-secrets" {
		t.Fatalf("dir = %q", inj.Secrets.Dir)
	}
}

// An ephemeral container attaches to a running pod, so the release check cannot
// help: the file already exists. Without this guard `kubectl debug` reads a
// secret straight out of a live pod.
func TestEphemeralContainerCannotMountReservedVolumes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		certVolume string
		mount      string
		ctrName    string
		target     string
		injected   bool
		wantOK     bool
	}{
		{name: "mounts secrets", mount: secretsVolumeName},
		{name: "mounts certs", mount: defaultCertVolumeName},
		{name: "mounts a renamed cert volume", certVolume: "my-certs", mount: "my-certs"},
		{name: "claims a reserved name", ctrName: reservedSecretContainerName, mount: "scratch"},
		{name: "mounts something else", mount: "scratch", wantOK: true},
		{name: "mounts nothing", wantOK: true},
		// The pod renamed its cert volume, so the default name is no longer
		// the one holding its key.
		{name: "default name after a rename", certVolume: "my-certs", mount: defaultCertVolumeName, wantOK: true},
		// Every container of an injected pod mounts c8s material, and a target
		// shares its process namespace.
		{name: "targets the cert sidecar", injected: true, target: reservedCertContainerName},
		{name: "targets the fetcher", injected: true, target: reservedSecretContainerName},
		{name: "targets the workload", injected: true, target: "app"},
		{name: "injected pod, no target", injected: true, wantOK: true},
		{name: "targets a container of a pod that was not injected", target: "app", wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := podWithApp()
			if tc.injected {
				mutateWithSecrets(t, pod, []string{"DB=/api/db"}, "")
			}
			if tc.certVolume != "" {
				pod.Annotations = map[string]string{AnnotationCertVolume: tc.certVolume}
			}
			name := tc.ctrName
			if name == "" {
				name = "debugger"
			}
			uid := int64(65532)
			ec := corev1.EphemeralContainer{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: name,
					SecurityContext: &corev1.SecurityContext{
						RunAsUser:                &uid,
						RunAsGroup:               &uid,
						RunAsNonRoot:             ptr.To(true),
						AllowPrivilegeEscalation: ptr.To(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					},
				},
				TargetContainerName: tc.target,
			}
			if tc.mount != "" {
				ec.VolumeMounts = []corev1.VolumeMount{{Name: tc.mount, MountPath: "/x"}}
			}
			pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{ec}

			err := rejectEphemeralReach(pod)
			if tc.wantOK && err != nil {
				t.Fatalf("rejected a harmless ephemeral container: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("accepted an ephemeral container that could read c8s material")
			}
		})
	}
}

// get-secret enforces these at pod start. Admission enforces them here too, so a
// typo in the annotation is a rejected manifest rather than a Running pod whose
// c8s-secret container crash-loops.
func TestSecretsSpecValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		specs   []string
		dir     string
		wantErr bool
	}{
		{name: "pair", specs: []string{"DB=/tenant-a/db", "HF=/tenant-a/hf-token"}},
		{name: "absolute dir", specs: []string{"DB=/tenant-a/db"}, dir: "/run/secrets"},
		{name: "no equals", specs: []string{"DB"}, wantErr: true},
		{name: "name with separator", specs: []string{"sub/DB=/tenant-a/db"}, wantErr: true},
		{name: "name is dotdot", specs: []string{"..=/tenant-a/db"}, wantErr: true},
		{name: "empty name", specs: []string{"=/tenant-a/db"}, wantErr: true},
		{name: "repeated name", specs: []string{"DB=/tenant-a/db", "DB=/tenant-a/other"}, wantErr: true},
		{name: "relative path", specs: []string{"DB=tenant-a/db"}, wantErr: true},
		{name: "trailing slash", specs: []string{"DB=/tenant-a/db/"}, wantErr: true},
		{name: "wildcard path", specs: []string{"DB=/tenant-a/*"}, wantErr: true},
		{name: "uncanonical path", specs: []string{"DB=/tenant-a/../db"}, wantErr: true},
		{name: "relative dir", specs: []string{"DB=/tenant-a/db"}, dir: "run/secrets", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := secretsSpec{Specs: tc.specs, Dir: tc.dir}.validate()
			if tc.wantErr && err == nil {
				t.Fatal("admitted a spec get-secret would reject")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("rejected a valid spec: %v", err)
			}
		})
	}
}
