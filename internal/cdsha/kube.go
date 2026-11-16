package cdsha

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// Kube keeps the chain in ConfigMaps: cds-<cluster>-head and, immutable,
// cds-<cluster>-e-<hash>. A Get without resourceVersion is a quorum read.
type Kube struct {
	ConfigMaps corev1client.ConfigMapInterface
	Cluster    string
}

// MaxKubeEntry is what one ConfigMap holds.
const MaxKubeEntry = 1 << 20

func (s *Kube) GetHead(ctx context.Context) ([]byte, error) {
	cm, err := s.ConfigMaps.Get(ctx, "cds-"+s.Cluster+"-head", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes get head: %w", err)
	}
	return []byte(cm.Data["head"]), nil
}

func (s *Kube) CASHead(ctx context.Context, old, next []byte) error {
	name := "cds-" + s.Cluster + "-head"
	var err error
	if old == nil {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name}, Data: map[string]string{"head": string(next)}}
		_, err = s.ConfigMaps.Create(ctx, cm, metav1.CreateOptions{})
	} else {
		var cm *corev1.ConfigMap
		if cm, err = s.ConfigMaps.Get(ctx, name, metav1.GetOptions{}); err == nil {
			if cm.Data["head"] != string(old) {
				return ErrConflict
			}
			// INVARIANT: cm keeps the resourceVersion it was read at, so the
			// update is refused if anything wrote the head since.
			cm.Data = map[string]string{"head": string(next)}
			_, err = s.ConfigMaps.Update(ctx, cm, metav1.UpdateOptions{})
		}
	}
	switch {
	case err == nil:
		return nil
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err), apierrors.IsNotFound(err):
		return ErrConflict
	}
	return fmt.Errorf("kubernetes cas head: %w", err)
}

func (s *Kube) PutEntry(ctx context.Context, hash cdschain.Hash, data []byte) error {
	if len(data) > MaxKubeEntry {
		return fmt.Errorf("entry %s is %d bytes; a ConfigMap holds %d", hash, len(data), MaxKubeEntry)
	}
	name := "cds-" + s.Cluster + "-e-" + hash.String()
	// An entry is immutable and named by its hash: one already stored is
	// not created again, since admission (a quota) charges refused creates.
	if _, err := s.ConfigMaps.Get(ctx, name, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("kubernetes get entry: %w", err)
	}
	immutable := true
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		BinaryData: map[string][]byte{"entry": data},
		Immutable:  &immutable,
	}
	_, err := s.ConfigMaps.Create(ctx, cm, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("kubernetes put entry: %w", err)
	}
	return nil
}

func (s *Kube) GetEntry(ctx context.Context, hash cdschain.Hash) ([]byte, error) {
	cm, err := s.ConfigMaps.Get(ctx, "cds-"+s.Cluster+"-e-"+hash.String(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes get entry: %w", err)
	}
	return cm.BinaryData["entry"], nil
}

// kubeconfig is the store credential: a kubeconfig cut down to one https
// server with inline CA data, one bearer token and a namespace. client-go's
// clientcmd never reads it, since a full kubeconfig can run a credential
// plugin or read files inside the VM, and the host writes this one.
type kubeconfig struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Clusters   []struct {
		Name    string `json:"name"`
		Cluster struct {
			Server                   string `json:"server"`
			CertificateAuthorityData []byte `json:"certificate-authority-data"`
			TLSServerName            string `json:"tls-server-name"`
		} `json:"cluster"`
	} `json:"clusters"`
	Users []struct {
		Name string `json:"name"`
		User struct {
			Token string `json:"token"`
		} `json:"user"`
	} `json:"users"`
	Contexts []struct {
		Name    string `json:"name"`
		Context struct {
			Cluster   string `json:"cluster"`
			User      string `json:"user"`
			Namespace string `json:"namespace"`
		} `json:"context"`
	} `json:"contexts"`
	CurrentContext string   `json:"current-context"`
	Preferences    struct{} `json:"preferences"`
}

// OpenKube reaches the Kubernetes API the credential names.
func OpenKube(credential []byte, cluster string) (*Kube, error) {
	var kc kubeconfig
	if err := yaml.UnmarshalStrict(credential, &kc); err != nil {
		return nil, fmt.Errorf("store credential: %w", err)
	}
	if kc.APIVersion != "v1" || kc.Kind != "Config" || len(kc.Clusters) != 1 || len(kc.Users) != 1 || len(kc.Contexts) != 1 {
		return nil, errors.New("store credential: want a v1 Config with one cluster, one user and one context")
	}
	c, u, x := kc.Clusters[0], kc.Users[0], kc.Contexts[0]
	server, err := url.Parse(c.Cluster.Server)
	switch {
	case kc.CurrentContext != x.Name || x.Context.Cluster != c.Name || x.Context.User != u.Name:
		return nil, errors.New("store credential: the current context must name the one cluster and user")
	case err != nil || server.Scheme != "https" || server.Host == "" || server.User != nil:
		return nil, fmt.Errorf("store credential: server %q is not an https URL", c.Cluster.Server)
	case len(c.Cluster.CertificateAuthorityData) == 0 || u.User.Token == "":
		return nil, errors.New("store credential: CA data and a token are required")
	}
	namespace := x.Context.Namespace
	if namespace == "" {
		namespace = "c8s-cds"
	}
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("store credential: namespace %q is not an RFC1123 label", namespace)
	}
	cfg := &rest.Config{
		Host:               c.Cluster.Server,
		BearerToken:        u.User.Token,
		TLSClientConfig:    rest.TLSClientConfig{CAData: c.Cluster.CertificateAuthorityData, ServerName: c.Cluster.TLSServerName},
		DisableCompression: true,
		// Every gossip-free read costs one request; the API server's own
		// flow control bounds the load.
		RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter(),
	}
	cfg.Wrap(func(next http.RoundTripper) http.RoundTripper { return capped{next} })
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &Kube{ConfigMaps: client.CoreV1().ConfigMaps(namespace), Cluster: cluster}, nil
}

// capped bounds every API server answer.
type capped struct{ next http.RoundTripper }

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if err == nil {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.LimitReader(resp.Body, MaxStoreAnswer), resp.Body}
	}
	return resp, err
}
