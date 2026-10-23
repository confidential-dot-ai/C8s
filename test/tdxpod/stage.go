package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// The connected fixture: three Services allocated before any VM exists, a
// signed Pod manifest running the pinned python image with app.py as its
// argv, and the launch bundles the paired CLI signs for the server and two
// Pods. It renders offline inputs only; nothing here talks to a cluster.

const pythonImage = "docker.io/library/python@sha256:5dcbe6043e931f65945060c7a991d55035191d7dfc52c8bed14468e95b8f7b9a"

//go:embed fixtures/pod-connected/app.py
var appScript string

var sides = []string{"server", "a", "b"}

// measuredRef is any image reference pinned by digest.
var measuredRef = regexp.MustCompile(`^\S+@sha256:[0-9a-f]{64}$`)

// excludedNetworks are guest-side or link-local ranges a Service IP must not
// overlap: the guest's masquerade network, the cluster service and pod
// ranges, the CDS point-to-point link and link-local.
var excludedNetworks = []netip.Prefix{netip.MustParsePrefix("10.0.2.0/24"), netip.MustParsePrefix("10.52.0.0/16"),
	netip.MustParsePrefix("10.53.0.0/16"), netip.MustParsePrefix("10.255.254.0/30"), netip.MustParsePrefix("169.254.0.0/16")}

type endpoint struct {
	IP  string `json:"ip"`
	UID string `json:"uid"`
}

func servicePorts(side string) []map[string]any {
	var ports []map[string]any
	if side == "server" {
		ports = []map[string]any{{"name": "cds", "port": 30808, "targetPort": 30808}, {"name": "api", "port": 6443, "targetPort": 6443}}
	} else {
		ports = []map[string]any{{"name": "app", "port": 8080, "targetPort": 8080}}
	}
	ports = append(ports, map[string]any{"name": "status", "port": 8443, "targetPort": 8443})
	for _, port := range ports {
		port["protocol"] = "TCP"
	}
	return ports
}

// serviceSpecs renders the three ClusterIP Services, without metadata: the
// owned-resource create names and labels them.
func serviceSpecs(name string) map[string]map[string]any {
	specs := map[string]map[string]any{}
	for _, side := range sides {
		specs[side] = map[string]any{"apiVersion": "v1", "kind": "Service", "spec": map[string]any{
			"type": "ClusterIP", "ipFamilyPolicy": "SingleStack", "ipFamilies": []string{"IPv4"},
			"publishNotReadyAddresses": true, "selector": map[string]string{"kubevirt.io/domain": name + "-" + side}, "ports": servicePorts(side)}}
	}
	return specs
}

// allocated checks the created Services and returns their addresses by side.
func allocated(services []*object, name string) (map[string]endpoint, error) {
	result := map[string]endpoint{}
	for _, service := range services {
		if service.Metadata.Namespace != namespace || service.Metadata.UID == "" {
			return nil, errors.New("Service namespace/UID is missing or different")
		}
		side := ""
		for _, s := range sides {
			if service.Metadata.Name == name+"-"+s {
				side = s
			}
		}
		if _, dup := result[side]; side == "" || dup {
			return nil, errors.New("unexpected or duplicate Service")
		}
		if len(service.Spec.Selector) != 1 || service.Spec.Selector["kubevirt.io/domain"] != name+"-"+side {
			return nil, errors.New("Service selector differs")
		}
		address, err := netip.ParseAddr(service.Spec.ClusterIP)
		if err != nil || !address.Is4() || address.IsLoopback() || address.IsUnspecified() {
			return nil, errors.New("Service IP overlaps a guest or excluded network")
		}
		for _, network := range excludedNetworks {
			if network.Contains(address) {
				return nil, errors.New("Service IP overlaps a guest or excluded network")
			}
		}
		required := map[int]int{8080: 8080, 8443: 8443}
		if side == "server" {
			required = map[int]int{30808: 30808, 8443: 8443, 6443: 6443}
		}
		actual := map[int]int{}
		for _, port := range service.Spec.Ports {
			if port.Protocol == "" || port.Protocol == "TCP" {
				actual[port.Port] = port.TargetPort
			}
		}
		if len(actual) != len(required) {
			return nil, errors.New("Service ports differ")
		}
		for port, target := range required {
			if actual[port] != target {
				return nil, errors.New("Service ports differ")
			}
		}
		result[side] = endpoint{IP: address.String(), UID: service.Metadata.UID}
	}
	ips := map[string]bool{}
	for _, e := range result {
		ips[e.IP] = true
	}
	if len(result) != 3 || len(ips) != 3 {
		return nil, errors.New("expected three distinct allocated Services")
	}
	return result, nil
}

// bundleInputs are the offline inputs of one acceptance run's bundle.
type bundleInputs struct {
	name, cli, manifest, manifestSHA256, source, meshImage, collectorURL, out string
	endpoints                                                                 map[string]endpoint
}

// identity is what the bundle renderer records about the signed inputs.
type identity struct {
	Source                string              `json:"source"`
	ManifestSHA256        string              `json:"manifestSHA256"`
	ApplicationImage      string              `json:"applicationImage"`
	MeshImage             string              `json:"meshImage"`
	Services              map[string]endpoint `json:"services"`
	SamePodManifestSHA256 string              `json:"samePodManifestSHA256"`
	ExpectedDigests       []string            `json:"expectedDigests"`
	Scope                 string              `json:"scope"`
}

func cli(executable string, args ...string) ([]byte, error) {
	result, err := execute(append([]string{executable}, args...), nil, nil, 60*time.Second)
	if err != nil {
		return nil, err
	}
	if result.timedOut || result.code != 0 {
		return nil, fmt.Errorf("c8s command failed: %s", printable(tail(result.stderr, 1000)))
	}
	return result.stdout, nil
}

func digestOf(ref string) string {
	return ref[strings.LastIndex(ref, "@")+1:]
}

// renderBundle writes the signed Pod manifest, workload allowlists, image
// policy and launch bundles into a fresh private directory.
func renderBundle(in bundleInputs) (*identity, error) {
	raw, err := os.ReadFile(in.manifest)
	if err != nil {
		return nil, err
	}
	if sha256Hex(raw) != in.manifestSHA256 {
		return nil, errors.New("exact-image manifest digest mismatch")
	}
	var manifest imageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Build.Platform != "tdx" {
		return nil, errors.New("complete TDX manifest required")
	}
	for _, register := range manifest.registers() {
		if !hexRTMR.MatchString(register) {
			return nil, errors.New("complete TDX manifest required")
		}
	}
	if !measuredRef.MatchString(in.meshImage) {
		return nil, errors.New("exact measured mesh image reference required")
	}
	if err := os.Mkdir(in.out, 0o700); err != nil {
		return nil, err
	}
	out, err := filepath.Abs(in.out)
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(out, "manifest.json"), raw); err != nil {
		return nil, err
	}
	derived, err := cli(in.cli, "measurements", "derive", in.manifest, "--tee", "tdx")
	if err != nil {
		return nil, err
	}
	var policy struct {
		Measurements []map[string]any `json:"measurements"`
	}
	if err := json.Unmarshal(derived, &policy); err != nil || len(policy.Measurements) != 1 {
		return nil, errors.New("exactly one TDX image tuple required")
	}
	var pinsList []map[string]any
	for _, side := range []string{"a", "b"} {
		if _, err := cli(in.cli, "keys", "new", "--out", filepath.Join(out, side+".key"), "--pub-out", filepath.Join(out, side+".pub")); err != nil {
			return nil, err
		}
		pub, err := os.ReadFile(filepath.Join(out, side+".pub"))
		if err != nil {
			return nil, err
		}
		pin := map[string]any{}
		for k, v := range policy.Measurements[0] {
			pin[k] = v
		}
		pin["name"], pin["approver_key"] = "pod-"+side, string(pub)
		pinsList = append(pinsList, pin)
	}
	if err := writeNew(filepath.Join(out, "pod-image-policy.json"), map[string]any{"measurements": pinsList}); err != nil {
		return nil, err
	}
	config := map[string]any{"peers": []string{in.endpoints["a"].IP, in.endpoints["b"].IP}, "dnsIPv4": "1.1.1.1", "podUID": in.name, "collectorURL": in.collectorURL}
	checkerConfig := map[string]any{}
	for k, v := range config {
		checkerConfig[k] = v
	}
	checkerConfig["mode"] = "checker"
	compact := func(v any) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	argv := []string{"-u", "-c", appScript, compact(config)}
	checkerArgv := []string{"-u", "-c", appScript, compact(checkerConfig)}
	security := map[string]any{"runAsNonRoot": true, "runAsUser": 1500, "runAsGroup": 1500, "allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []string{"ALL"}}}
	container := map[string]any{"name": "app", "image": pythonImage, "command": []string{"/usr/local/bin/python3"}, "args": argv,
		"securityContext": security, "ports": []map[string]any{{"name": "http", "containerPort": 8080, "protocol": "TCP"}},
		"readinessProbe": map[string]any{"httpGet": map[string]any{"path": "/ready", "port": 8080}, "periodSeconds": 5, "timeoutSeconds": 2, "failureThreshold": 1},
		"livenessProbe":  map[string]any{"httpGet": map[string]any{"path": "/live", "port": 8080}, "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 6},
		"resources":      map[string]any{"requests": map[string]string{"cpu": "100m", "memory": "64Mi"}, "limits": map[string]string{"cpu": "1", "memory": "256Mi"}}}
	checker := map[string]any{"name": "checker", "image": pythonImage, "command": []string{"/usr/local/bin/python3"}, "args": checkerArgv,
		"securityContext": security, "resources": map[string]any{"requests": map[string]string{"cpu": "50m", "memory": "32Mi"}, "limits": map[string]string{"cpu": "1", "memory": "128Mi"}}}
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "connected", "namespace": "acceptance", "uid": in.name},
		"spec": map[string]any{"automountServiceAccountToken": false, "restartPolicy": "Never", "containers": []map[string]any{container, checker}}}
	podJSON, err := encode(pod)
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(out, "pod.json"), podJSON); err != nil {
		return nil, err
	}
	rule := func(args []string) map[string]any {
		return map[string]any{"digest": digestOf(pythonImage), "image": pythonImage,
			"command": map[string]any{"policy": "exact", "argv": []string{"/usr/local/bin/python3"}},
			"args":    map[string]any{"policy": "exact", "argv": args}, "mounts": map[string]any{"policy": "any"}}
	}
	workloads := map[string]any{"connected": map[string]any{"containers": []map[string]any{rule(argv), rule(checkerArgv)}}}
	if err := writeNew(filepath.Join(out, "pod-workloads.json"), map[string]any{"schema": "c8s.allowlist/v1", "workloads": workloads}); err != nil {
		return nil, err
	}
	workloads["pod-mesh-membership"] = map[string]any{"containers": []map[string]any{{"digest": digestOf(in.meshImage), "image": in.meshImage,
		"command": map[string]any{"policy": "exact", "argv": []string{"/app/c8s", "armtls-mesh"}},
		"args":    map[string]any{"policy": "exact", "argv": []string{"--cert-path=/etc/c8s/certs/tls.crt", "--key-path=/etc/c8s/certs/tls.key", "--ca-path=/etc/c8s/certs/ca.crt"}},
		"mounts":  map[string]any{"policy": "any"}}}}
	if err := writeNew(filepath.Join(out, "server-workloads.json"), map[string]any{"schema": "c8s.allowlist/v1", "workloads": workloads}); err != nil {
		return nil, err
	}
	if _, err := cli(in.cli, "node", "launch-config", "new", "--out", filepath.Join(out, "server"), "--cluster-id", in.name,
		"--server-name", in.name+"-server", "--image-manifest", filepath.Join(out, "manifest.json"),
		"--server-address", in.endpoints["server"].IP, "--workloads", filepath.Join(out, "server-workloads.json"),
		"--pod-image-policy-file", filepath.Join(out, "pod-image-policy.json")); err != nil {
		return nil, err
	}
	for _, side := range []string{"a", "b"} {
		if _, err := cli(in.cli, "node", "launch-config", "new-pod", "--out", filepath.Join(out, side), "--cluster-id", in.name,
			"--name", in.name+"-"+side, "--image-manifest", filepath.Join(out, "manifest.json"), "--launch-key", filepath.Join(out, side+".key"),
			"--server-address", in.endpoints["server"].IP, "--server-public-key", filepath.Join(out, "server/server/pubkey"),
			"--pod-manifest", filepath.Join(out, "pod.json"), "--workloads", filepath.Join(out, "pod-workloads.json"),
			"--mesh-peer", in.endpoints["a"].IP+":8080", "--mesh-peer", in.endpoints["b"].IP+":8080"); err != nil {
			return nil, err
		}
	}
	id := &identity{Source: in.source, ManifestSHA256: in.manifestSHA256, ApplicationImage: pythonImage, MeshImage: in.meshImage,
		Services: in.endpoints, SamePodManifestSHA256: sha256Hex(podJSON), ExpectedDigests: []string{digestOf(pythonImage), digestOf(in.meshImage)},
		Scope: "native KubeVirt TDX hardware; no Cloud API or dynamic endpoint discovery claim"}
	return id, writeNew(filepath.Join(out, "identity.json"), id)
}
