package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The boot diagnostic boots the rke2-tdx-dev image published for the commit
// in POD_DIAGNOSTIC_SOURCE, which also supplies the CLI that signs the Pod
// fixture. The manual image workflow refuses a c8s_ref that is not that
// commit, so the image profile and the components come from the same source.
// It is a manual, disposable boot diagnostic; never acceptance.

const maxBootBytes = 262144

//go:embed fixtures/pod-diagnostic.json
var bootFixture []byte

// bootPins identifies the image under diagnosis and is recorded in identity.json.
type bootPins struct {
	Source         string `json:"source"`
	ArtifactTag    string `json:"artifactTag"`
	Image          string `json:"image"`
	ManifestSHA256 string `json:"manifestSHA256"`
	DiskSHA256     string `json:"diskSHA256"`
	Scope          string `json:"scope,omitempty"`
}

func validateBootManifest(data []byte, p bootPins) error {
	if len(data) > 65536 || sha256Hex(data) != p.ManifestSHA256 {
		return errors.New("diagnostic manifest digest differs")
	}
	var m imageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("diagnostic manifest: %w", err)
	}
	if m.Inputs.BaseImage.SHA256 != p.DiskSHA256 {
		return errors.New("diagnostic disk digest differs")
	}
	for _, k := range []string{"mrtd", "rtmr1", "rtmr2"} {
		if !hexRTMR.MatchString(m.TDX[k]) {
			return errors.New("incomplete TDX identity")
		}
	}
	return nil
}

// resolveBootImage finds the dev image published for one source commit,
// naming the missing tag and the build command otherwise.
func resolveBootImage(source, bearer string) (bootPins, error) {
	if !hexCommit.MatchString(source) {
		return bootPins{}, errors.New("POD_DIAGNOSTIC_SOURCE must be the full 40-hex commit the image was built from")
	}
	tag, cdiTag := "rke2-tdx-dev-"+source[:7], "rke2-tdx-dev-cdi-"+source[:7]
	hint := fmt.Sprintf("; build it with: gh workflow run c8s-image-manual.yml --ref <branch at %s> -f dev=true -f c8s_ref=%s", source[:7], source[:7])
	body, _, err := registry("/manifests/"+tag, bearer, "application/vnd.oci.image.manifest.v1+json")
	if err != nil {
		return bootPins{}, err
	}
	if body == nil {
		return bootPins{}, fmt.Errorf("no published diagnostic artifact ghcr.io/%s:%s%s", imageRepo, tag, hint)
	}
	if len(body) > 65536 {
		return bootPins{}, errors.New("oversized artifact manifest")
	}
	var artifact struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &artifact); err != nil {
		return bootPins{}, fmt.Errorf("%s: %w", tag, err)
	}
	layers := map[string]string{}
	for _, layer := range artifact.Layers {
		layers[layer.Annotations["org.opencontainers.image.title"]] = layer.Digest
	}
	for _, name := range []string{"manifest.json", "disk.raw"} {
		if !hexDigest.MatchString(layers[name]) {
			return bootPins{}, fmt.Errorf("%s does not carry manifest.json and disk.raw layers", tag)
		}
	}
	_, headers, err := registry("/manifests/"+cdiTag, bearer, "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json")
	if err != nil {
		return bootPins{}, err
	}
	if headers == nil {
		return bootPins{}, fmt.Errorf("no published diagnostic image ghcr.io/%s:%s%s", imageRepo, cdiTag, hint)
	}
	cdi := headers.Get("Docker-Content-Digest")
	if !hexDigest.MatchString(cdi) {
		return bootPins{}, fmt.Errorf("%s resolved to no content digest", cdiTag)
	}
	return bootPins{Source: source, ArtifactTag: tag, Image: "ghcr.io/" + imageRepo + "@" + cdi,
		ManifestSHA256: strings.TrimPrefix(layers["manifest.json"], "sha256:"),
		DiskSHA256:     strings.TrimPrefix(layers["disk.raw"], "sha256:")}, nil
}

type bootDiagnostic struct {
	*owned
	pins *bootPins
}

func newBootDiagnostic(root, run, attempt, repo string) (*bootDiagnostic, error) {
	o, err := newOwned(root, run, attempt, repo, "c8s-poddiag", "pod-diagnostic")
	if err != nil {
		return nil, err
	}
	return &bootDiagnostic{owned: o}, nil
}

// prepare resolves the image, checks the paired CLI and signs the fixture.
func (d *bootDiagnostic) prepare() error {
	bearer, err := bearerToken()
	if err != nil {
		return err
	}
	p, err := resolveBootImage(os.Getenv("POD_DIAGNOSTIC_SOURCE"), bearer)
	if err != nil {
		return err
	}
	d.pins = &p
	data, _, err := registry("/blobs/sha256:"+p.ManifestSHA256, bearer, "application/octet-stream")
	if err != nil {
		return err
	}
	if data == nil {
		return errors.New("the artifact's manifest.json blob is missing from the registry")
	}
	if err := validateBootManifest(data, p); err != nil {
		return err
	}
	manifest := filepath.Join(d.evidence, "manifest.json")
	if err := write(manifest, data); err != nil {
		return err
	}
	cli := filepath.Join(d.private, "c8s")
	version, err := command([]string{"go", "version", "-m", cli}, nil, 30*time.Second)
	if err != nil {
		return err
	}
	if !bytes.Contains(version, []byte("vcs.revision="+p.Source)) || !bytes.Contains(version, []byte("vcs.modified=false")) {
		return errors.New("CLI does not match the clean diagnostic source")
	}
	var parts map[string]json.RawMessage
	if err := json.Unmarshal(bootFixture, &parts); err != nil {
		return fmt.Errorf("fixture: %w", err)
	}
	for _, name := range []string{"pod", "workloads"} {
		if err := write(filepath.Join(d.private, name+".json"), append(bytes.Clone(parts[name]), '\n')); err != nil {
			return err
		}
	}
	common := []string{cli, "node", "launch-config"}
	if _, err := command(append(common, "new", "--out", filepath.Join(d.private, "server"), "--cluster-id", d.name,
		"--image-manifest", manifest), nil, 30*time.Second); err != nil {
		return err
	}
	if _, err := command(append(common, "new-pod", "--out", filepath.Join(d.private, "bundle"), "--cluster-id", d.name,
		"--image-manifest", manifest, "--pod-manifest", filepath.Join(d.private, "pod.json"),
		"--workloads", filepath.Join(d.private, "workloads.json"), "--server-address", "10.255.255.1",
		"--server-public-key", filepath.Join(d.private, "server/server/pubkey")), nil, 30*time.Second); err != nil {
		return err
	}
	identity := p
	identity.Scope = "boot diagnostics only; CDS deliberately unavailable"
	if err := write(filepath.Join(d.evidence, "identity.json"), identity); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "kubectl", "-n", namespace, "auth", "can-i", "create", "services")
	out, probeErr := probe.Output()
	authority := map[string]any{"namespace": namespace, "verb": "create", "resource": "services"}
	if ctx.Err() != nil {
		authority["observation"] = "timed out"
	} else {
		authority["allowed"] = probeErr == nil && string(bytes.TrimSpace(out)) == "yes"
		authority["exitCode"] = probe.ProcessState.ExitCode()
	}
	return write(filepath.Join(d.evidence, "service-authority.json"), authority)
}

func rootClaim() map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
		"spec": map[string]any{"accessModes": []string{"ReadWriteOnce"}, "storageClassName": "local-path",
			"resources": map[string]any{"requests": map[string]string{"storage": "80Gi"}}}}
}

// binderPod pins the root claim to a TDX node before the import; cpu and
// memory are the lane's capacity reservation.
func binderPod(name, cpu, memory string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "spec": map[string]any{
		"restartPolicy": "Never", "activeDeadlineSeconds": 1500, "automountServiceAccountToken": false,
		"nodeSelector":    map[string]string{"kubevirt.io/tdx": "true"},
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 65534, "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
		"containers": []map[string]any{{"name": "pause", "image": pauseImage,
			"resources":       map[string]any{"requests": map[string]string{"cpu": cpu, "memory": memory}, "limits": map[string]string{"cpu": cpu, "memory": memory}},
			"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}}}},
		"volumes": []map[string]any{{"name": "root", "persistentVolumeClaim": map[string]any{"claimName": name + "-root", "readOnly": true}}}}}
}

// importRoot binds the root claim on a TDX node, starts the CDI import of
// image into it and waits for the import to succeed.
func (o *owned) importRoot(image, cpu, memory string, deadlineOf func(time.Duration) time.Time, failed, timedOut string) error {
	if _, err := o.createFn("pvc", "-root", rootClaim()); err != nil {
		return err
	}
	if _, err := o.createFn("pod", "-binder", binderPod(o.name, cpu, memory)); err != nil {
		return err
	}
	deadline := deadlineOf(300 * time.Second)
	var pvc *object
	for scheduled := false; !scheduled; {
		if !now().Before(deadline) {
			return errors.New("TDX capacity binder did not schedule")
		}
		var pod *object
		var err error
		if pvc, err = o.get("pvc", "-root", deadline); err != nil {
			return err
		}
		if pod, err = o.get("pod", "-binder", deadline); err != nil {
			return err
		}
		if node := pod.Spec.NodeName; node != "" && pvc.Status.Phase == "Bound" {
			if pvc.Metadata.Annotations["volume.kubernetes.io/selected-node"] != node {
				return errors.New("root selected another node")
			}
			scheduled = true
			continue
		}
		pause(deadline, 5*time.Second)
	}
	if _, err := kube([]string{"annotate", "pvc", o.name + "-root", "--resource-version=" + pvc.Metadata.ResourceVersion,
		"cdi.kubevirt.io/storage.import.source=registry", "cdi.kubevirt.io/storage.import.endpoint=docker://" + image,
		"cdi.kubevirt.io/storage.contentType=kubevirt", "cdi.kubevirt.io/storage.import.secretName=ghcr-pull"}, nil, 30*time.Second); err != nil {
		return err
	}
	if err := o.removeFn("pod", "-binder", time.Time{}); err != nil {
		return err
	}
	deadline = deadlineOf(1200 * time.Second)
	for {
		if !now().Before(deadline) {
			return errors.New(timedOut)
		}
		pvc, err := o.get("pvc", "-root", deadline)
		if err != nil {
			return err
		}
		switch pvc.Metadata.Annotations["cdi.kubevirt.io/storage.pod.phase"] {
		case "Failed":
			return errors.New(failed)
		case "Succeeded":
			return nil
		}
		pause(deadline, 10*time.Second)
	}
}

// launchSecret carries only the three bundle files a guest reads; no copy is
// staged on disk.
func launchSecret(dir string) (map[string]any, error) {
	data := map[string]string{}
	for _, name := range []string{"pubkey", "launch.yaml", "launch.yaml.sig"} {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		data[name] = base64.StdEncoding.EncodeToString(content)
	}
	return map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "data": data}, nil
}

// vmSpec is a TDX VirtualMachine on the shared read-only root, booting once
// with the launch Secret as its second disk and, with scratch set, a
// scratch disk the server role formats.
func vmSpec(vmName, rootClaim, secret string, cores int, memory string, scratch string) map[string]any {
	disks := []map[string]any{{"name": "rootdisk", "disk": map[string]any{"bus": "virtio", "readonly": true}}, {"name": "opkey", "disk": map[string]any{"bus": "virtio"}}}
	volumes := []map[string]any{
		{"name": "rootdisk", "persistentVolumeClaim": map[string]string{"claimName": rootClaim}},
		{"name": "opkey", "secret": map[string]string{"secretName": secret, "volumeLabel": "opkeydata"}}}
	if scratch != "" {
		disks = append(disks, map[string]any{"name": "scratch", "disk": map[string]any{"bus": "virtio"}, "serial": "confai-scratch"})
		volumes = append(volumes, map[string]any{"name": "scratch", "persistentVolumeClaim": map[string]string{"claimName": scratch}})
	}
	return map[string]any{"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachine", "spec": map[string]any{
		"runStrategy": "Once", "template": map[string]any{"metadata": map[string]any{"labels": map[string]string{"kubevirt.io/domain": vmName}}, "spec": map[string]any{
			"nodeSelector": map[string]string{"kubevirt.io/tdx": "true"}, "terminationGracePeriodSeconds": 10,
			"domain": map[string]any{"cpu": map[string]any{"model": "host-passthrough", "cores": cores}, "memory": map[string]string{"guest": memory},
				"resources": map[string]any{"requests": map[string]string{"memory": memory}}, "firmware": map[string]any{"bootloader": map[string]any{"efi": map[string]bool{"secureBoot": false}}},
				"launchSecurity": map[string]any{"tdx": map[string]any{}}, "devices": map[string]any{"autoattachVSOCK": true, "logSerialConsole": true, "rng": map[string]any{},
					"disks": disks, "interfaces": []map[string]any{{"name": "default", "masquerade": map[string]any{}}}}},
			"networks": []map[string]any{{"name": "default", "pod": map[string]any{}}}, "volumes": volumes}}}}
}

func (d *bootDiagnostic) vm() map[string]any {
	return vmSpec(d.name, d.name+"-root", d.name+"-opkey", 2, "8Gi", "")
}

// provision imports the image into a run-owned root on the TDX node and
// starts the VM with the signed launch bundle.
func (d *bootDiagnostic) provision() error {
	if d.pins == nil {
		return errors.New("provision needs the resolved image pins from prepare")
	}
	if err := d.importRoot(d.pins.Image, "2", "8Gi", func(d time.Duration) time.Time { return now().Add(d) },
		"diagnostic CDI import failed", "diagnostic CDI import timed out"); err != nil {
		return err
	}
	secret, err := launchSecret(filepath.Join(d.private, "bundle/pod"))
	if err != nil {
		return err
	}
	if _, err := d.createFn("secret", "-opkey", secret); err != nil {
		return err
	}
	_, err = d.createFn("vm", "", d.vm())
	return err
}

func (d *bootDiagnostic) evidenceFile(index int, name string) string {
	return filepath.Join(d.evidence, fmt.Sprintf("%03d-%s", index, name))
}

// launcherLogs reads bounded logs of the VM's launcher Pod into evidence:
// both ends of the serial log (a dev image forwards its journal there) and
// the compute container log; each read is rechecked against the launcher and
// VMI UIDs before it is published.
func (o *owned) launcherLogs(prefix, vmName, vmiUID string, pod *object, deadline time.Time) error {
	read := func(args []string) ([]byte, error) {
		timeout, err := budget(deadline, 30*time.Second)
		if err != nil {
			return nil, err
		}
		return kube(args, nil, timeout)
	}
	name := pod.Metadata.Name
	serial := "/var/run/kubevirt-private/" + vmiUID + "/virt-serial0-log"
	for kind, args := range map[string][]string{
		"serial":      {"exec", name, "-c", "compute", "--", "head", "-c", fmt.Sprint(maxBootBytes), serial},
		"serial-tail": {"exec", name, "-c", "compute", "--", "tail", "-c", fmt.Sprint(maxBootBytes), serial},
		"compute.log": {"logs", name, "-c", "compute", "--tail=500", "--limit-bytes=" + fmt.Sprint(maxBootBytes), "--timestamps=true"},
	} {
		err := func() error {
			data, err := read(args)
			if err != nil {
				return err
			}
			if len(data) > maxBootBytes {
				return errors.New("oversized diagnostic output")
			}
			launcher, err := read([]string{"get", "pod", name, "-o", "json"})
			if err != nil {
				return err
			}
			current, err := parseObject(launcher)
			if err != nil || current.Metadata.UID != pod.Metadata.UID {
				return errors.New("launcher replaced during capture")
			}
			if vmiUID != "" {
				vmi, err := read([]string{"get", "vmi", vmName, "-o", "json"})
				if err != nil {
					return err
				}
				current, err := parseObject(vmi)
				if err != nil || current.Metadata.UID != vmiUID {
					return errors.New("VMI replaced during capture")
				}
			}
			return write(filepath.Join(o.evidence, prefix+kind), data)
		}()
		if err != nil {
			if err := write(filepath.Join(o.evidence, prefix+kind+"-error.json"), map[string]string{"error": err.Error()}); err != nil {
				return err
			}
		}
	}
	return nil
}

// capture records the VM, its VMI and launcher Pod and their logs, reading
// only objects owned through the VM; it reports whether the VMI reached a
// final phase.
func (d *bootDiagnostic) capture(index int, deadline time.Time) (bool, error) {
	read := func(args []string) (*object, error) {
		timeout, err := budget(deadline, 30*time.Second)
		if err != nil {
			return nil, err
		}
		return kubeObject(args, nil, timeout)
	}
	vm, err := d.get("vm", "", deadline)
	if err != nil {
		return false, err
	}
	if err := write(d.evidenceFile(index, "vm.json"), vm.raw); err != nil {
		return false, err
	}
	vmi, err := read([]string{"get", "vmi", d.name, "--ignore-not-found", "-o", "json"})
	if err != nil {
		return false, err
	}
	if vmi == nil {
		return false, nil
	}
	if !vmi.ownedBy("VirtualMachine", vm.Metadata.UID) {
		return false, errors.New("VMI owner differs")
	}
	if err := write(d.evidenceFile(index, "vmi.json"), vmi.raw); err != nil {
		return false, err
	}
	pods, err := read([]string{"get", "pods", "-l", "kubevirt.io/domain=" + d.name, "-o", "json"})
	if err != nil {
		return false, err
	}
	if pods == nil {
		return false, errors.New("launcher listing returned nothing")
	}
	prefix := fmt.Sprintf("%03d-", index)
	for _, item := range pods.Items {
		pod, err := parseObject(item)
		if err != nil {
			return false, err
		}
		if !pod.ownedBy("VirtualMachineInstance", vmi.Metadata.UID) {
			return false, errors.New("launcher owner differs")
		}
		if err := write(d.evidenceFile(index, "launcher.json"), []byte(item)); err != nil {
			return false, err
		}
		if err := d.launcherLogs(prefix, d.name, vmi.Metadata.UID, pod, deadline); err != nil {
			return false, err
		}
	}
	return vmi.Status.Phase == "Failed" || vmi.Status.Phase == "Succeeded", nil
}

func (d *bootDiagnostic) observe() error {
	deadline := now().Add(600 * time.Second)
	for index := range 40 {
		final, err := d.capture(index, deadline)
		if err != nil {
			return err
		}
		if final || !now().Before(deadline) {
			break
		}
		pause(deadline, 10*time.Second)
	}
	for _, pattern := range []string{"*-serial", "*-serial-tail", "*-compute.log"} {
		matches, _ := filepath.Glob(filepath.Join(d.evidence, pattern))
		for _, path := range matches {
			if info, err := os.Stat(path); err == nil && info.Size() > 0 {
				return nil
			}
		}
	}
	return errors.New("no serial or launcher log was captured; inspect native status evidence")
}

func runBoot(mode string) error {
	d, err := newBootDiagnostic(filepath.Join(os.Getenv("RUNNER_TEMP"), "pod-diagnostic"),
		os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_REPOSITORY"))
	if err != nil {
		return err
	}
	if mode == "cleanup" {
		return d.cleanup()
	}
	entries, err := d.resources()
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("diagnostic run already owns resources")
	}
	err = d.prepare()
	if err == nil {
		err = d.provision()
	}
	if err == nil {
		err = d.observe()
	}
	if err != nil {
		_ = write(filepath.Join(d.evidence, "failure.json"), map[string]string{"error": err.Error(), "type": errorClass(err)})
		if d.hasVM() {
			if _, captureErr := d.capture(999, now().Add(60*time.Second)); captureErr != nil {
				_ = write(filepath.Join(d.evidence, "failure-capture.json"), map[string]string{"error": captureErr.Error()})
			}
		}
		return err
	}
	fmt.Fprintln(progressOut, "Boot evidence captured; this diagnostic does not establish image or Pod connectivity acceptance.")
	return nil
}

// errorClass names an error's Go type without package or pointer.
func errorClass(err error) string {
	name := fmt.Sprintf("%T", err)
	name = strings.TrimPrefix(name, "*")
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
}
