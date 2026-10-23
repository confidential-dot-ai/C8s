package launchconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// The enrollment wire contract, which cloud's managed Kubernetes enrollment
// service serves (docs/managed-kubernetes/enrollment.md in that repository):
//
//	POST /v1/challenge {"machineUID"}                         -> {"nonce"}
//	POST /v1/enroll    {"machineUID", "nonce", "certificate"} -> {"material", "providerID"}
//
// Both go over armTLS to a management image the launch document pins. The
// certificate is a self-signed armTLS certificate whose evidence binds a fresh
// node key and the nonce, so the service sees this boot's evidence, fresh.
// material is released once per Machine UID, and its exact bytes must hash to
// the document's managed.bootstrapDigest.
const (
	challengePath = "/v1/challenge"
	enrollPath    = "/v1/enroll"
	// maxMaterial bounds the response: CAs and a config are a few KiB.
	maxMaterial = 1 << 20
)

type challengeRequest struct {
	MachineUID string `json:"machineUID"`
}

type challengeResponse struct {
	Nonce []byte `json:"nonce"`
}

type enrollRequest struct {
	MachineUID  string `json:"machineUID"`
	Nonce       []byte `json:"nonce"`
	Certificate []byte `json:"certificate"`
}

type enrollResponse struct {
	Material   json.RawMessage `json:"material"`
	ProviderID string          `json:"providerID"`
}

// Material is the RKE2 role material a management cluster releases for one
// Machine: its role, the RKE2 settings it adds to the image's, and the CA
// files a control-plane member starts with.
type Material struct {
	Role   Role           `json:"role"`
	Config map[string]any `json:"config"`
	Files  []MaterialFile `json:"files,omitempty"`
}

// MaterialFile is one file under the RKE2 server's TLS directories.
type MaterialFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
}

// EnrollConfig selects the trusted local facilities enrollment uses.
type EnrollConfig struct {
	Platform             string
	AttestationAPIURL    string
	MeasuredPoliciesFile string
	// Timeout bounds the whole enrollment, retries included. A refusal ends
	// it at once: the Machine is left for its health check to replace.
	Timeout time.Duration
	RootDir string
}

func (c EnrollConfig) path(absolute string) string { return Config{RootDir: c.RootDir}.path(absolute) }

// ErrRefused is an enrollment service's refusal, which retrying cannot change.
var ErrRefused = errors.New("enrollment refused")

// newEnrollClient is a package var so tests can serve enrollment over plain
// TLS; the real client verifies the service's armTLS evidence.
var newEnrollClient = func(policy *armtls.VerifyPolicy) (*http.Client, error) {
	tlsCfg, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: policy})
	if err != nil {
		return nil, err
	}
	return armtls.HTTPClient(tlsCfg), nil
}

// newCertProvider makes the node's nonce-bound enrollment certificate.
var newCertProvider = func(cfg EnrollConfig, api string, nonce []byte) armtls.CertProvider {
	return &armtls.SelfSignedProvider{
		Platform:         cfg.Platform,
		AttestFunc:       attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), api),
		MeasuredPolicies: armtls.NewJournal(cfg.MeasuredPoliciesFile),
		Opts:             &armtls.CertOptions{TTL: 5 * time.Minute},
		Nonce:            nonce,
	}
}

// Enroll runs after a managed launch is staged. It fetches this Machine's
// role material from the enrollment service the signed document names,
// checks it against the document, writes it, and writes the role marker last.
func Enroll(ctx context.Context, cfg EnrollConfig) error {
	if _, err := os.Stat(cfg.path(enrollMarker)); err != nil {
		return fmt.Errorf("no managed launch is staged: %w", err)
	}
	doc, err := LoadStaged(cfg.path(DefaultStagedPath))
	if err != nil {
		return err
	}
	if !doc.IsManaged() {
		return fmt.Errorf("the staged launch is not %s", SchemaVersionManaged)
	}
	api := cfg.AttestationAPIURL
	if api == "" {
		api = DefaultAttestationAPIURL
	}
	client, err := newEnrollClient(&armtls.VerifyPolicy{Policy: doc.Managed.ManagementPolicy(), AttestationApiURL: api})
	if err != nil {
		return fmt.Errorf("enrollment client: %w", err)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var resp *enrollResponse
	for delay := time.Second; ; delay = min(2*delay, 30*time.Second) {
		resp, err = enrollOnce(ctx, client, cfg, api, doc.Managed)
		if err == nil || errors.Is(err, ErrRefused) {
			break
		}
		fmt.Fprintf(os.Stderr, "enroll: %v; retrying in %s\n", err, delay)
		select {
		case <-ctx.Done():
			return fmt.Errorf("enroll: %w (last error: %v)", ctx.Err(), err)
		case <-time.After(delay):
		}
	}
	if err != nil {
		return err
	}
	return stageMaterial(cfg, doc, resp)
}

func enrollOnce(ctx context.Context, client *http.Client, cfg EnrollConfig, api string, m *Managed) (*enrollResponse, error) {
	var challenge challengeResponse
	if err := post(ctx, client, m.Enrollment.URL+challengePath, challengeRequest{MachineUID: m.MachineUID}, &challenge); err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	if len(challenge.Nonce) < 16 || len(challenge.Nonce) > 64 {
		return nil, fmt.Errorf("challenge: nonce of %d bytes, want 16..64", len(challenge.Nonce))
	}
	cert, _, err := newCertProvider(cfg, api, challenge.Nonce).Provision(ctx)
	if err != nil {
		return nil, fmt.Errorf("node evidence: %w", err)
	}
	var resp enrollResponse
	req := enrollRequest{MachineUID: m.MachineUID, Nonce: challenge.Nonce, Certificate: cert.Certificate[0]}
	if err := post(ctx, client, m.Enrollment.URL+enrollPath, req, &resp); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	return &resp, nil
}

func post(ctx context.Context, client *http.Client, url string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxMaterial+1))
	if err != nil {
		return err
	}
	if len(payload) > maxMaterial {
		return fmt.Errorf("response exceeds %d bytes", maxMaterial)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrRefused, strings.TrimSpace(string(payload)))
	default:
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(payload)))
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

var providerIDRE = regexp.MustCompile(`^cc://[a-z0-9][a-z0-9-]{0,62}$`)

// stageMaterial checks the released material against the signed document and
// the image, then writes it. It writes the role marker last, as Stage does.
func stageMaterial(cfg EnrollConfig, doc *Document, resp *enrollResponse) error {
	sum := sha256.Sum256(resp.Material)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != doc.Managed.BootstrapDigest {
		return fmt.Errorf("released material is %s, the launch document names %s", got, doc.Managed.BootstrapDigest)
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Material))
	dec.DisallowUnknownFields()
	var m Material
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("decode released material: %w", err)
	}
	if m.Role != doc.Role {
		return fmt.Errorf("released material is for a %s, this node is a %s", m.Role, doc.Role)
	}
	if !providerIDRE.MatchString(resp.ProviderID) {
		return fmt.Errorf("provider ID %q must be cc://<instance id>", resp.ProviderID)
	}
	base, err := readBaseConfig(cfg.path(rke2BaseConfig))
	if err != nil {
		return err
	}
	fragment, err := managedConfig(base, m, resp.ProviderID)
	if err != nil {
		return err
	}
	outputs := []outputFile{{managedFragment, fragment}}
	for _, f := range m.Files {
		if err := checkMaterialFile(doc.Role, f); err != nil {
			return err
		}
		outputs = append(outputs, outputFile{f.Path, f.Content})
	}
	for _, out := range outputs {
		p := cfg.path(out.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return fmt.Errorf("create output parent: %w", err)
		}
		if err := fileutil.WriteAtomic(p, out.data, 0o600); err != nil {
			return fmt.Errorf("stage %s: %w", out.path, err)
		}
	}
	marker := agentMarker
	if doc.Role == Server {
		marker = serverMarker
	}
	return fileutil.WriteAtomic(cfg.path(marker), nil, 0o600)
}

const rke2BaseConfig = "/etc/rancher/rke2/config.yaml"

// materialFileRE names the CA certificates and keys CAPRKE2 writes for a
// control-plane member. Every one is a secret or sits beside one, so all are
// written root-only.
var materialFileRE = regexp.MustCompile(`^/var/lib/rancher/rke2/server/tls/(etcd/)?[a-z][a-z0-9-]*\.(crt|key)$`)

func checkMaterialFile(role Role, f MaterialFile) error {
	if role != Server {
		return fmt.Errorf("released file %s: only a control-plane member receives files", f.Path)
	}
	if path.Clean(f.Path) != f.Path || !materialFileRE.MatchString(f.Path) {
		return fmt.Errorf("released file %s is not an RKE2 server CA file", f.Path)
	}
	if len(f.Content) == 0 {
		return fmt.Errorf("released file %s is empty", f.Path)
	}
	return nil
}

func readBaseConfig(p string) (map[string]any, error) {
	data, err := readBounded(p, MaxDocumentSize)
	if err != nil {
		return nil, fmt.Errorf("read the image's RKE2 config: %w", err)
	}
	var base map[string]any
	if err := yaml.Unmarshal(data, &base); err != nil {
		return nil, fmt.Errorf("parse the image's RKE2 config: %w", err)
	}
	return base, nil
}

// managedListKeys are the RKE2 list settings management adds to: the drop-in
// appends them (key+) instead of replacing the image's values.
var managedListKeys = []string{
	"tls-san", "node-label", "node-taint", "disable",
	"kubelet-arg", "kube-apiserver-arg", "kube-controller-manager-arg", "kube-scheduler-arg", "etcd-arg",
}

// managedScalarKeys are the RKE2 settings management sets outright. The
// image sets none of them.
var managedScalarKeys = []string{
	"token", "agent-token", "server", "cloud-provider-name", "disable-cloud-controller",
	"secrets-encryption", "etcd-snapshot-schedule-cron", "etcd-snapshot-retention",
	"etcd-expose-metrics", "write-kubeconfig-mode", "cluster-domain",
}

// refusedArgs are component flags that would point a component at code or
// keys outside the image, or replace the provider ID enrollment sets.
var refusedArgs = []string{
	"provider-id", "image-credential-provider-config", "image-credential-provider-bin-dir",
	"token-auth-file", "authorization-webhook-config-file", "authentication-token-webhook-config-file",
	"admission-control-config-file", "authorization-config", "audit-policy-file", "audit-log-path",
}

// managedConfig renders 60-managed.yaml. A setting the image fixes, such as
// the CNI or the cluster's address ranges, may only repeat the image's value,
// and is then left to the image.
func managedConfig(base map[string]any, m Material, providerID string) ([]byte, error) {
	out := map[string]any{}
	keys := make([]string, 0, len(m.Config))
	for k := range m.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []error
	for _, k := range keys {
		v := m.Config[k]
		switch {
		case slices.Contains(managedListKeys, k):
			values, ok := stringList(v)
			if !ok {
				errs = append(errs, fmt.Errorf("RKE2 setting %s must be a list of strings", k))
				continue
			}
			if strings.HasSuffix(k, "-arg") {
				for _, a := range values {
					name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
					if slices.Contains(refusedArgs, name) {
						errs = append(errs, fmt.Errorf("RKE2 setting %s=%s is refused", k, a))
					}
				}
			}
			out[k+"+"] = values
		case slices.Contains(managedScalarKeys, k):
			if _, fixed := base[k]; fixed {
				errs = append(errs, fmt.Errorf("RKE2 setting %s is fixed by the image", k))
				continue
			}
			out[k] = v
		default:
			fixed, ok := base[k]
			if !ok {
				errs = append(errs, fmt.Errorf("RKE2 setting %s is not one management may set", k))
				continue
			}
			if !sameSetting(fixed, v) {
				errs = append(errs, fmt.Errorf("RKE2 setting %s is fixed by the image to %v", k, fixed))
			}
		}
	}
	if s, _ := out["token"].(string); s == "" {
		errs = append(errs, errors.New("released material has no RKE2 token"))
	}
	if m.Role == Agent {
		if s, _ := out["server"].(string); s == "" {
			errs = append(errs, errors.New("released agent material names no server"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	args, _ := out["kubelet-arg+"].([]string)
	out["kubelet-arg+"] = append(args, "provider-id="+providerID)
	return yaml.Marshal(out)
}

// stringList reads a YAML/JSON list of strings, or a single string.
func stringList(v any) ([]string, bool) {
	switch v := v.(type) {
	case string:
		return []string{v}, true
	case []string:
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// sameSetting compares an image setting with management's, treating a
// one-item list and its item as the same (CAPRKE2 writes cni as a list).
func sameSetting(image, managed any) bool {
	a, aok := stringList(image)
	b, bok := stringList(managed)
	if aok && bok {
		return slices.Equal(a, b)
	}
	return fmt.Sprint(image) == fmt.Sprint(managed)
}
