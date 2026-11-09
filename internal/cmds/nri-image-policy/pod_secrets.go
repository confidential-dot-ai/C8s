package nriimagepolicy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/secretbroker"
)

// Pod secret delivery (docs/pod-secrets.md). The signed pod manifest names
// the secrets its pod reads in podSecretsAnnotation. Once the pod holds its
// CDS leaf, the guest broker asks CDS for each over mutual TLS with that leaf
// and the client document; CDS brokers the release to the KMS. The values go
// into the pod's memory emptyDir podSecretVolume, which only workload
// containers may mount, read-only. One fetch per pod: no rotation.
const (
	podSecretsAnnotation = "confidential.ai/pod-secrets"
	podSecretVolume      = "c8s-pod-secrets"
	podSecretFileMode    = 0o444
	podSecretFirstRetry  = 2 * time.Second
	podSecretMaxRetry    = 30 * time.Second
	maxPodSecrets        = 8
)

var openPodSecretRoot = openVerifiedPodSecretRoot

// podSecretNames parses the manifest's comma-separated secret names. The
// kubelet runs the static pod the signed assignment carries, so the
// annotation is the assignment's.
func podSecretNames(pod *api.PodSandbox) ([]string, error) {
	raw := strings.TrimSpace(pod.GetAnnotations()[podSecretsAnnotation])
	if raw == "" {
		return nil, nil
	}
	var names []string
	seen := map[string]bool{}
	for name := range strings.SplitSeq(raw, ",") {
		name = strings.TrimSpace(name)
		if secretbroker.ValidSecretName(name) != nil || seen[name] {
			return nil, fmt.Errorf("%s: %q must be a distinct secret name of [A-Za-z0-9._-]", podSecretsAnnotation, name)
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) > maxPodSecrets {
		return nil, fmt.Errorf("%s names more than %d secrets", podSecretsAnnotation, maxPodSecrets)
	}
	return names, nil
}

func podSecretSource(pod *api.PodSandbox) string {
	return kubeletRoot + "/pods/" + pod.GetUid() + "/volumes/" + emptyDirPlugin + "/" + podSecretVolume
}

// podSecretReader checks a container's final mounts against the secret
// volume, as podCredentialSource does for the mesh credentials: a platform
// container never mounts it, a workload container only read-only, only the
// exact memory-backed volume and never through a parent bind.
func (p *plugin) podSecretReader(pod *api.PodSandbox, ctr *api.Container, role string, mounts []allowlist.ObservedMount) error {
	if !p.cfg.podRole() || strings.ContainsAny(pod.GetUid(), "/\\") || pod.GetUid() == "" {
		return nil
	}
	base := podSecretSource(pod)
	reads := false
	for _, mount := range ctr.GetMounts() {
		src := path.Clean(mount.GetSource())
		parent := path.IsAbs(src) && (src == "/" || strings.HasPrefix(base, src+"/"))
		if src != base && !strings.HasPrefix(src, base+"/") && !parent {
			continue
		}
		if role != "" || mount.GetSource() != base || !fileBind(mount) || !endsReadOnly(mount) {
			return errors.New("only a workload container may mount the exact Pod secret volume, read-only")
		}
		reads = true
	}
	verified := false
	for _, mount := range mounts {
		if mount.Volume != podSecretVolume {
			continue
		}
		if role != "" || mount.Class != allowlist.MountEmptyDir || mount.Storage != allowlist.MountMemory || !mount.ReadOnly {
			return errors.New("the Pod secret mount must be a read-only memory emptyDir of a workload container")
		}
		verified = true
	}
	if reads && !verified {
		return errors.New("the Pod secret volume has no verified memory-backed mount evidence")
	}
	if names, err := podSecretNames(pod); reads && (err != nil || len(names) == 0) {
		return errors.New("the Pod secret volume is mounted but the manifest requests no secret")
	}
	return nil
}

// podLeafCertificate presents the pod's current CDS leaf, as published to
// the mesh endpoint's credential volume, to CDS.
func (p *plugin) podLeafCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	p.podMu.Lock()
	b := p.podBroker
	var root *os.Root
	if b != nil {
		root = b.root
	}
	p.podMu.Unlock()
	if root == nil {
		return nil, errors.New("no Pod credential volume")
	}
	chain, err := root.ReadFile("tls.crt")
	if err != nil {
		return nil, fmt.Errorf("no published Pod leaf: %w", err)
	}
	key, err := root.ReadFile("tls.key")
	if err != nil {
		return nil, fmt.Errorf("no published Pod key: %w", err)
	}
	defer clear(key)
	cert, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// runPodSecretWorker fetches the manifest's secrets once, retrying until CDS
// releases all of them: before the first leaf is published, and while the
// KMS refuses, a request fails and is tried again.
func (p *plugin) runPodSecretWorker() {
	b := p.podBroker
	names, err := podSecretNames(b.pod)
	if err != nil {
		p.logger.Error("Pod secrets not requested", "error", err)
		return
	}
	if len(names) == 0 {
		return
	}
	if b.secretsClient == nil {
		p.logger.Error("Pod secrets requested but the broker has no CDS client for them")
		return
	}
	doc := []byte(p.cfg.Pod.ClientDocument)
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		retry := podSecretFirstRetry
		for {
			err := p.fetchPodSecrets(b.ctx, b.secretsClient, names, doc)
			if err == nil {
				p.logger.Info("Pod secrets delivered", "count", len(names))
				return
			}
			if b.ctx.Err() != nil {
				return
			}
			p.logger.Info("Pod secrets not yet released", "error", err)
			select {
			case <-b.ctx.Done():
				return
			case <-time.After(retry):
			}
			retry = min(2*retry, podSecretMaxRetry)
		}
	}()
}

// fetchPodSecrets publishes every secret or none, so a consumer never sees
// part of its set.
func (p *plugin) fetchPodSecrets(ctx context.Context, client *http.Client, names []string, doc []byte) error {
	values := make(map[string][]byte, len(names))
	defer func() {
		for _, v := range values {
			clear(v)
		}
	}()
	for _, name := range names {
		value, err := requestPodSecret(ctx, client, p.cfg.pullURL(), name, doc)
		if err != nil {
			return fmt.Errorf("secret %s: %w", name, err)
		}
		values[name] = value
	}
	p.podMu.Lock()
	defer p.podMu.Unlock()
	b := p.podBroker
	if b.terminal != nil {
		return b.terminal
	}
	root, err := openPodSecretRoot(podSecretSource(b.pod))
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range names {
		if err := fileutil.WriteAtomicRoot(root, name, values[name], podSecretFileMode); err != nil {
			return fmt.Errorf("write Pod secret %s: %w", name, err)
		}
	}
	return nil
}

func requestPodSecret(ctx context.Context, client *http.Client, cdsURL, name string, doc []byte) ([]byte, error) {
	body, err := json.Marshal(secretbroker.PodRequest{Secret: name, ClientDocument: doc})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(cdsURL, "/")+secretbroker.PodRoute, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*secretbroker.MaxValue+4096))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDS answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var answer secretbroker.PodResponse
	err = json.Unmarshal(raw, &answer)
	clear(raw)
	if err != nil {
		return nil, fmt.Errorf("decode Pod secret response: %w", err)
	}
	return answer.Value, nil
}
