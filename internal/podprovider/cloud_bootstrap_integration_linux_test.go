//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	podfixture "github.com/confidential-dot-ai/c8s/test/tdxpod/fixtures/pod-connected"
)

func (r *cloudRun) cli(ctx context.Context, args ...string) ([]byte, error) {
	return r.runTool(ctx, r.cfg.CLIFile, args...)
}

// The timeout lane needs an independently ready guest, without the connected
// fixture's peer receipts, readiness cycle or long-running checker.
const cloudVerificationScript = `from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path in ("/live", "/ready") else 404)
        self.end_headers()

    def log_message(self, *_args):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
`

func (r *cloudRun) workload(side string, peer *endpoint) (*corev1.Pod, map[string]any, error) {
	program, names := podfixture.Script, []string{"app", "checker"}
	verification := r.cfg.scenario() != "connected"
	if verification {
		if side != "a" || peer != nil {
			return nil, nil, errors.New("standalone scenario requires one A workload")
		}
		program, names = cloudVerificationScript, []string{"app"}
		if r.cfg.scenario() == "cds-outage" {
			program = cloudCDSScript
		}
	}
	var packed bytes.Buffer
	w := zlib.NewWriter(&packed)
	if _, err := w.Write([]byte(program)); err != nil {
		return nil, nil, err
	}
	if err := w.Close(); err != nil {
		return nil, nil, err
	}
	script := "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode('" + base64.StdEncoding.EncodeToString(packed.Bytes()) + "')),'<string>','exec'))"
	config := map[string]any{"role": "responder", "podUID": r.ledger.Run + "-" + side, "initiatorPodUID": r.ledger.Run + "-b", "dnsIPv4": "1.1.1.1"}
	if side == "b" {
		if peer == nil {
			return nil, nil, errors.New("B requires A's allocated endpoint")
		}
		config["role"] = "initiator"
		config["peer"] = map[string]any{"host": peer.Host, "port": peer.Port, "podUID": r.ledger.Run + "-a"}
	}
	var containers, rules []any
	for _, name := range names {
		command := []string{"/usr/local/bin/python3"}
		args := []string{"-u", "-c", script}
		if !verification {
			mode := map[string]any{}
			for k, v := range config {
				mode[k] = v
			}
			if name == "checker" {
				mode["mode"] = "checker"
			}
			raw, err := json.Marshal(mode)
			if err != nil {
				return nil, nil, err
			}
			args = append(args, string(raw))
		}
		c := map[string]any{"name": name, "image": podfixture.PythonImage, "command": command, "args": args, "securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": 1500, "runAsGroup": 1500, "allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []string{"ALL"}}}, "resources": map[string]any{"requests": map[string]string{"cpu": "100m", "memory": "64Mi"}, "limits": map[string]string{"cpu": "500m", "memory": "256Mi"}}}
		if name == "app" {
			c["ports"] = []any{map[string]any{"name": "http", "containerPort": 8080, "protocol": "TCP"}}
			c["readinessProbe"] = map[string]any{"httpGet": map[string]any{"path": "/ready", "port": 8080}, "periodSeconds": 5, "timeoutSeconds": 2, "failureThreshold": 1}
			c["livenessProbe"] = map[string]any{"httpGet": map[string]any{"path": "/live", "port": 8080}, "periodSeconds": 10, "timeoutSeconds": 2, "failureThreshold": 6}
		}
		if r.cfg.scenario() == "cds-outage" {
			c["volumeMounts"] = []any{map[string]any{"name": "restart", "mountPath": "/restart"}}
		}
		containers = append(containers, c)
		rules = append(rules, map[string]any{"digest": strings.Split(podfixture.PythonImage, "@")[1], "image": podfixture.PythonImage, "command": map[string]any{"policy": "exact", "argv": command}, "args": map[string]any{"policy": "exact", "argv": args}, "mounts": map[string]any{"policy": "any"}})
	}
	wire := map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "cloud-" + side, "namespace": "tenant", "annotations": map[string]string{Annotation: "true"}}, "spec": map[string]any{"automountServiceAccountToken": false, "restartPolicy": "Never", "containers": containers, "schedulingGates": []any{map[string]any{"name": "acceptance.confidential.ai/durable-intent"}}}}
	if r.cfg.scenario() == "cds-outage" {
		spec := wire["spec"].(map[string]any)
		spec["restartPolicy"] = "Always"
		spec["volumes"] = []any{map[string]any{"name": "restart", "emptyDir": map[string]any{"medium": "Memory", "sizeLimit": "1Mi"}}}
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return nil, nil, err
	}
	var pod corev1.Pod
	if err = json.Unmarshal(raw, &pod); err != nil {
		return nil, nil, err
	}
	policy := map[string]any{"schema": "c8s.allowlist/v1", "workloads": map[string]any{"cloud-" + side: map[string]any{"containers": rules}}}
	return &pod, policy, nil
}

func (r *cloudRun) bootstrap(ctx context.Context) (*Config, *corev1.Pod, endpoint, error) {
	var cds endpoint
	a, workloads, err := r.workload("a", nil)
	if err != nil {
		return nil, nil, cds, err
	}
	providerKey, providerPub := filepath.Join(r.dir, "provider.key"), filepath.Join(r.dir, "provider.pub")
	if _, err = r.cli(ctx, "keys", "new", "--out", providerKey, "--pub-out", providerPub); err != nil {
		return nil, nil, cds, err
	}
	mesh := map[string]any{"containers": []any{map[string]any{"digest": strings.Split(r.cfg.MeshImage, "@")[1], "image": r.cfg.MeshImage, "command": map[string]any{"policy": "exact", "argv": []string{"/app/c8s", "armtls-mesh"}}, "args": map[string]any{"policy": "exact", "argv": []string{"--cert-path=/etc/c8s/certs/tls.crt", "--key-path=/etc/c8s/certs/tls.key", "--ca-path=/etc/c8s/certs/ca.crt"}}, "mounts": map[string]any{"policy": "any"}}}}
	if r.cfg.scenario() == "cds-outage" {
		delete(workloads["workloads"].(map[string]any), "cloud-a")
	}
	workloads["workloads"].(map[string]any)["pod-mesh-membership"] = mesh
	workloadPath := filepath.Join(r.dir, "workloads.json")
	if err = cloudWrite(workloadPath, workloads); err != nil {
		return nil, nil, cds, err
	}
	document, err := r.cdsBundle(ctx, workloadPath, providerPub)
	if err != nil {
		return nil, nil, cds, err
	}
	key := r.ledger.Run + "-cds"
	labels := map[string]string{"acceptance-run": r.ledger.Run, "acceptance-side": "cds"}
	req := r.cdsRequest(key, labels, document)
	r.ledger.Owned["cds"] = &cloudOwned{Key: key, Image: r.cfg.CDSImage, LaunchFileSHA256: cloudHash(document), Labels: labels, IntentAt: time.Now().UTC(), Attempted: true}
	if err = cloudWrite(filepath.Join(r.dir, "cds-request.json"), req); err != nil {
		return nil, nil, cds, err
	}
	if err = r.save(); err != nil {
		return nil, nil, cds, err
	}
	var response json.RawMessage
	if err = r.api.do(ctx, http.MethodPost, "/v1/instances", key, req, &response); err != nil {
		// These responses are definite pre-persistence refusals. Transport errors,
		// conflicts and server errors remain uncertain and require lookup recovery.
		for _, status := range []string{"400", "401", "403", "404", "422"} {
			if strings.HasPrefix(err.Error(), "cloud returned HTTP "+status+" (") {
				r.ledger.Owned["cds"].Attempted = false
				if saveErr := r.save(); saveErr != nil {
					return nil, nil, cds, saveErr
				}
				break
			}
		}
		return nil, nil, cds, err
	}
	until, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	for {
		in, readErr := r.getOwned(until, "cds")
		if readErr != nil {
			return nil, nil, cds, readErr
		}
		if in != nil {
			cds, err = cloudEndpoint(in, "cds")
			if err == nil && cds.Port == 8443 {
				_, err = r.ca(until, cds)
				if err == nil {
					break
				}
			}
		}
		if err = cloudPause(until, 10*time.Second); err != nil {
			return nil, nil, cds, errors.New("CDS did not present its attested CA before deadline")
		}
	}
	// Signed writes must be newer than the CDS process's startup replay window.
	if err = cloudPause(ctx, 61*time.Second); err != nil {
		return nil, nil, cds, err
	}
	if err = r.cdsInitialPolicy(ctx, cds, workloadPath); err != nil {
		return nil, nil, cds, err
	}
	cfg := &Config{ProviderID: r.ledger.Run, NodeName: r.ledger.Run, Namespace: "podcloud-system", CloudURL: r.cfg.CloudURL, CloudTokenFile: r.cfg.TokenFile, Image: r.cfg.Image, ImageManifestFile: r.cfg.ManifestFile, LaunchKeyFile: providerKey, ServerAddress: cds.Host, ServerPublicKeyFile: filepath.Join(r.dir, "server.pub"), CDSAddress: net.JoinHostPort(cds.Host, strconv.Itoa(cds.Port)), CDSImagePolicyFile: filepath.Join(r.dir, "cds/cds-pin.json"), WorkloadsFile: workloadPath, ClusterID: r.ledger.Run, Size: r.cfg.Size, Location: r.cfg.Location, VCPUs: r.cfg.VCPUs, MemoryMiB: r.cfg.MemoryMiB, ReservedMemoryMiB: 1024, MaxPods: 2, PublicIP: "shared"}
	if r.cfg.scenario() == "warm-assignment" {
		cfg.WarmTarget = 1
	}
	if err = cloudWrite(filepath.Join(r.dir, "provider.json"), cfg); err != nil {
		return nil, nil, cds, err
	}
	cfg, err = LoadConfig(filepath.Join(r.dir, "provider.json"))
	if err == nil && r.cfg.scenario() == "cds-outage" {
		var appPolicy map[string]any
		a, appPolicy, err = r.cdsWorkload(cds)
		if err == nil {
			err = cloudWrite(filepath.Join(r.dir, "cds-app-policy.json"), appPolicy)
		}
		if err == nil {
			err = r.cdsPolicyUpdate(ctx, cfg, cds, true)
		}
	}
	return cfg, a, cds, err
}

func (r *cloudRun) cdsOptions(cds endpoint) []string {
	return []string{"--url", "https://" + net.JoinHostPort(cds.Host, strconv.Itoa(cds.Port)), "--image-policy-file", filepath.Join(r.dir, "cds/cds-pin.json")}
}
func (r *cloudRun) ca(ctx context.Context, cds endpoint) ([]byte, error) {
	path := filepath.Join(r.dir, "mesh-ca.pem")
	args := append([]string{"cds", "ca"}, r.cdsOptions(cds)...)
	args = append(args, "--out", path)
	if _, err := r.cli(ctx, args...); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
func (r *cloudRun) policy(ctx context.Context, cds endpoint) (*pkgallowlist.Allowlist, []byte, error) {
	raw, err := r.cli(ctx, append([]string{"allowlist", "export"}, r.cdsOptions(cds)...)...)
	if err != nil {
		return nil, nil, err
	}
	policy, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := policy.Canonical()
	return policy, canonical, err
}

func (r *cloudRun) addB(ctx context.Context, cds endpoint, peer endpoint, cfg *Config) (*corev1.Pod, *Config, []byte, error) {
	b, update, err := r.workload("b", &peer)
	if err != nil {
		return nil, nil, nil, err
	}
	baseline, _, err := r.policy(ctx, cds)
	if err != nil {
		return nil, nil, nil, err
	}
	authored, err := os.ReadFile(cfg.WorkloadsFile)
	if err != nil {
		return nil, nil, nil, err
	}
	base, err := pkgallowlist.ParseJSON(authored)
	if err != nil {
		return nil, nil, nil, err
	}
	for name, want := range base.Workloads {
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(baseline.Workloads[name])
		if !bytes.Equal(a, b) {
			return nil, nil, nil, errors.New("owned CDS policy changed before B admission")
		}
	}
	if _, exists := baseline.Workloads["cloud-b"]; exists {
		return nil, nil, nil, errors.New("B policy already exists before owned update")
	}
	raw, err := json.Marshal(update)
	if err != nil {
		return nil, nil, nil, err
	}
	added, err := pkgallowlist.ParseJSON(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	baseline.Workloads["cloud-b"] = added.Workloads["cloud-b"]
	expected, err := baseline.Canonical()
	if err != nil {
		return nil, nil, nil, err
	}
	path := filepath.Join(r.dir, "b-workloads.json")
	if err = cloudWriteBytes(path, raw); err != nil {
		return nil, nil, nil, err
	}
	args := append([]string{"allowlist", "apply", path}, r.cdsOptions(cds)...)
	args = append(args, "--operator-key", filepath.Join(r.dir, "cds-operator.key"))
	if _, err = r.cli(ctx, args...); err != nil {
		return nil, nil, nil, err
	}
	_, actual, err := r.policy(ctx, cds)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(actual, expected) {
		return nil, nil, nil, errors.New("signed CDS policy update differs from exact merge")
	}
	base.Workloads["cloud-b"] = added.Workloads["cloud-b"]
	authored, err = base.Canonical()
	if err != nil {
		return nil, nil, nil, err
	}
	if err = cloudWriteBytes(cfg.WorkloadsFile, authored); err != nil {
		return nil, nil, nil, err
	}
	cfg.MeshPeers = []string{net.JoinHostPort(peer.Host, strconv.Itoa(peer.Port))}
	if err = cloudWrite(filepath.Join(r.dir, "provider.json"), cfg); err != nil {
		return nil, nil, nil, err
	}
	cfg, err = LoadConfig(filepath.Join(r.dir, "provider.json"))
	return b, cfg, expected, err
}

// Kept separate from observer records: Kubernetes-generated UIDs authorize only
// the exact provider's idempotency keys, never discovery by a display name.
func (r *cloudRun) recordPod(pod *corev1.Pod, cfg *Config, side string) error {
	key := identityKey(cfg.ProviderID, string(pod.UID))
	return r.updateLedger(func(ledger *cloudLedger) error {
		if r.cfg.scenario() == "warm-assignment" {
			if ledger.Pods == nil {
				ledger.Pods = map[string]cloudPodIntent{}
			}
			if _, exists := ledger.Pods[side]; exists {
				return errors.New("submitted Pod identity already exists")
			}
			ledger.Pods[side] = cloudPodIntent{UID: string(pod.UID), Key: key}
		} else {
			ledger.Owned[side] = &cloudOwned{Key: key, UID: string(pod.UID), Image: cfg.Image, LaunchKey: cfg.pub, Labels: map[string]string{"podcvm-provider": cfg.ProviderID, "podcvm-uid": strings.TrimPrefix(key, "podcvm-")}, IntentAt: time.Now().UTC(), Attempted: true}
		}
		return nil
	})
}
