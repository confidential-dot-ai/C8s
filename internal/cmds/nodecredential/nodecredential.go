// Package nodecredential is the kubelet's credential plugin on a node of a
// hosted Kubernetes cluster: it attests the node to the cluster's CDS and
// hands the kubelet the join token CDS mints (docs/node-tokens.md).
//
// The kubelet runs it from the exec user of its bootstrap kubeconfig, with
// provideClusterInfo set, so the plugin sees the API server and CA the
// kubelet is about to trust. It checks both against the pins it was started
// with before it attests: join data the host can rewrite must not be able to
// point the kubelet, and its token, at another server.
package nodecredential

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"

	"github.com/confidential-dot-ai/c8s/internal/nodetoken"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// ExecInfoEnv is where the kubelet passes the exec plugin its input.
const ExecInfoEnv = "KUBERNETES_EXEC_INFO"

// Pins are what the node holds its join to: the API server's hostname and
// the SHA-256 of the one CA certificate it may present.
type Pins struct {
	APIServer string
	CASHA256  string
}

// checkCluster refuses cluster information that does not match the pins: an
// https server at the pinned hostname on 443, verified, with exactly the
// pinned CA. The token is minted for that hostname, so passing this check is
// what keeps it from reaching any other server.
func checkCluster(info *clientauthv1.ExecCredential, pins Pins) error {
	if info == nil || info.APIVersion != clientauthv1.SchemeGroupVersion.String() {
		return fmt.Errorf("%s must carry a %s ExecCredential", ExecInfoEnv, clientauthv1.SchemeGroupVersion)
	}
	cluster := info.Spec.Cluster
	if cluster == nil {
		return errors.New("no cluster information: the kubeconfig's exec user must set provideClusterInfo: true")
	}
	u, err := url.Parse(cluster.Server)
	if err != nil {
		return fmt.Errorf("cluster server %q: %w", cluster.Server, err)
	}
	if u.Scheme != "https" || u.Hostname() != pins.APIServer || (u.Port() != "" && u.Port() != "443") ||
		(u.Path != "" && u.Path != "/") || u.User != nil {
		return fmt.Errorf("cluster server %q is not the pinned https://%s", cluster.Server, pins.APIServer)
	}
	if cluster.TLSServerName != "" && cluster.TLSServerName != pins.APIServer {
		return fmt.Errorf("cluster tls-server-name %q is not the pinned %s", cluster.TLSServerName, pins.APIServer)
	}
	if cluster.InsecureSkipTLSVerify {
		return errors.New("cluster skips TLS verification")
	}
	fingerprint, err := soleCertificateSHA256(cluster.CertificateAuthorityData)
	if err != nil {
		return fmt.Errorf("cluster CA: %w", err)
	}
	if !strings.EqualFold(fingerprint, pins.CASHA256) {
		return fmt.Errorf("cluster CA sha256 %s is not the pinned %s", fingerprint, pins.CASHA256)
	}
	return nil
}

// soleCertificateSHA256 is the SHA-256 of the one certificate in pemData. A
// bundle with more than one is refused, since any of them would be trusted.
func soleCertificateSHA256(pemData []byte) (string, error) {
	var der []byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		if der != nil {
			return "", errors.New("more than one certificate")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", err
		}
		der = block.Bytes
	}
	if der == nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("want exactly one PEM certificate")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// loadOrCreateNodeKey reads the node key, or makes it on first use. The key
// names the node, so it is kept for the node's life: a new key is a new node.
// It must be readable by root alone.
func loadOrCreateNodeKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createNodeKey(path)
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("node key %s has mode %o; it must be readable by its owner alone", path, info.Mode().Perm())
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("node key %s is not a PEM EC private key", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("node key %s: %w", path, err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("node key %s is not P-256", path)
	}
	return key, nil
}

func createNodeKey(path string) (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// O_EXCL: two plugin runs racing on first use must not each keep a key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return loadOrCreateNodeKey(path)
	}
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return key, f.Close()
}

// NodeName is the name this node joins under, derived from its key as CDS
// derives the token's subject.
func NodeName(keyPath string) (string, error) {
	key, err := loadOrCreateNodeKey(keyPath)
	if err != nil {
		return "", err
	}
	return nodetoken.Subject(&key.PublicKey)
}

// obtainFunc is the CDS call, a parameter so the plugin's checks are tested
// without a TEE.
type obtainFunc func(ctx context.Context, attestationApiURL string, nodeKey *ecdsa.PublicKey, audience string) (types.NodeTokenResponse, error)

// credential runs the plugin once: read the kubelet's input, check it
// against the pins, attest, and write the ExecCredential.
func credential(ctx context.Context, execInfo string, pins Pins, keyPath, attestationApiURL string,
	obtain obtainFunc, out io.Writer) error {
	if execInfo == "" {
		return fmt.Errorf("%s is empty: run as the kubelet's exec credential plugin", ExecInfoEnv)
	}
	var info clientauthv1.ExecCredential
	if err := json.Unmarshal([]byte(execInfo), &info); err != nil {
		return fmt.Errorf("%s: %w", ExecInfoEnv, err)
	}
	if err := checkCluster(&info, pins); err != nil {
		return err
	}
	key, err := loadOrCreateNodeKey(keyPath)
	if err != nil {
		return err
	}
	resp, err := obtain(ctx, attestationApiURL, &key.PublicKey, pins.APIServer)
	if err != nil {
		return fmt.Errorf("node token: %w", err)
	}
	expires := metav1.NewTime(resp.ExpiresAt)
	return json.NewEncoder(out).Encode(clientauthv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{APIVersion: clientauthv1.SchemeGroupVersion.String(), Kind: "ExecCredential"},
		Status: &clientauthv1.ExecCredentialStatus{
			Token:               resp.Token,
			ExpirationTimestamp: &expires,
		},
	})
}

// requestTimeout bounds one plugin run, under the kubelet's own patience.
const requestTimeout = 90 * time.Second
