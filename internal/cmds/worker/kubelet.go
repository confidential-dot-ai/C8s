package worker

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// INVARIANT: on a worker image only stage writes under kubernetesDir; the
// kubelet keeps its own kubeconfig and certificates under /var/lib/kubelet.
const kubernetesDir = "/run/kubernetes"

// The kubelet's inputs.
const (
	bootstrapKubeconfigPath = kubernetesDir + "/bootstrap-kubelet.conf"
	kubeletConfigPath       = kubernetesDir + "/kubelet-config.yaml"
	kubeletEnvPath          = kubernetesDir + "/kubelet.env"
	staticPodPath           = kubernetesDir + "/manifests"
)

const (
	containerdEndpoint = "unix:///run/containerd/containerd.sock"
	// resolvConf lists systemd-resolved's upstream servers, which pods reach.
	resolvConf = "/run/systemd/resolve/resolv.conf"
	// clusterDomain is the domain the baked CoreDNS serves.
	clusterDomain = "cluster.local"
)

// bootstrapTokenPattern is a Kubernetes bootstrap token, "<id>.<secret>", and
// at most one trailing newline.
var bootstrapTokenPattern = regexp.MustCompile(`^([a-z0-9]{6}\.[a-z0-9]{16})\n?$`)

// maxBootstrapTokenFile bounds the read; a token file is at most 24 bytes.
const maxBootstrapTokenFile = 64

// readBootstrapToken reads the token from path, which must itself be a
// regular file, not a link, FIFO or device. Errors carry neither its bytes nor
// the path, in case the token was passed for the path.
func readBootstrapToken(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return "", tokenFileError(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", tokenFileError(err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("--bootstrap-token-file is not a regular file")
	}
	data, err := readutil.ReadAll(f, maxBootstrapTokenFile)
	if err != nil {
		return "", tokenFileError(err)
	}
	match := bootstrapTokenPattern.FindSubmatch(data)
	if match == nil {
		return "", errors.New("--bootstrap-token-file does not hold a bootstrap token: <6 lowercase letters or digits>.<16 lowercase letters or digits>")
	}
	return string(match[1]), nil
}

// tokenFileError is err without the path a *fs.PathError carries.
func tokenFileError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return fmt.Errorf("--bootstrap-token-file: %w", err)
}

// nodeName identifies the worker slot at address.
func nodeName(address [4]byte) string {
	return fmt.Sprintf("n-%d-%d-%d-%d", address[0], address[1], address[2], address[3])
}

// kubeletConfiguration is the part of kubelet.config.k8s.io/v1beta1 a worker
// sets, every field written.
type kubeletConfiguration struct {
	APIVersion               string                `json:"apiVersion"`
	Kind                     string                `json:"kind"`
	Authentication           kubeletAuthentication `json:"authentication"`
	Authorization            kubeletAuthorization  `json:"authorization"`
	CgroupDriver             string                `json:"cgroupDriver"`
	ClusterDNS               []string              `json:"clusterDNS"`
	ClusterDomain            string                `json:"clusterDomain"`
	ContainerRuntimeEndpoint string                `json:"containerRuntimeEndpoint"`
	EnableDebuggingHandlers  bool                  `json:"enableDebuggingHandlers"`
	EnableSystemLogHandler   bool                  `json:"enableSystemLogHandler"`
	EnableProfilingHandler   bool                  `json:"enableProfilingHandler"`
	EnableDebugFlagsHandler  bool                  `json:"enableDebugFlagsHandler"`
	ReadOnlyPort             int32                 `json:"readOnlyPort"`
	ResolvConf               string                `json:"resolvConf"`
	RotateCertificates       bool                  `json:"rotateCertificates"`
	StaticPodPath            string                `json:"staticPodPath"`
}

type kubeletAuthentication struct {
	Anonymous kubeletSwitch `json:"anonymous"`
	Webhook   kubeletSwitch `json:"webhook"`
}

type kubeletSwitch struct {
	Enabled bool `json:"enabled"`
}

type kubeletAuthorization struct {
	Mode string `json:"mode"`
}

func kubeletConfig(k Kubernetes) ([]byte, error) {
	return yaml.Marshal(kubeletConfiguration{
		APIVersion: "kubelet.config.k8s.io/v1beta1",
		Kind:       "KubeletConfiguration",
		Authentication: kubeletAuthentication{
			Anonymous: kubeletSwitch{Enabled: false},
			Webhook:   kubeletSwitch{Enabled: true},
		},
		Authorization:            kubeletAuthorization{Mode: "Webhook"},
		CgroupDriver:             "systemd",
		ClusterDNS:               []string{k.ClusterDNS},
		ClusterDomain:            clusterDomain,
		ContainerRuntimeEndpoint: containerdEndpoint,
		// INVARIANT: all false, so the kubelet serves no exec, attach,
		// port-forward, logs, checkpoint or profiling.
		EnableDebuggingHandlers: false,
		EnableSystemLogHandler:  false,
		EnableProfilingHandler:  false,
		EnableDebugFlagsHandler: false,
		ReadOnlyPort:            0,
		ResolvConf:              resolvConf,
		RotateCertificates:      true,
		StaticPodPath:           staticPodPath,
	})
}

// bootstrapKubeconfig is the kubeconfig the kubelet requests its client
// certificate with. The kubelet copies its cluster, the document's API server
// and CA, into the kubeconfig it then writes for itself.
func bootstrapKubeconfig(k Kubernetes, token string) ([]byte, error) {
	config := clientcmdapi.NewConfig()
	config.Clusters["cluster"] = &clientcmdapi.Cluster{
		Server:                   (&url.URL{Scheme: "https", Host: k.APIServer}).String(),
		CertificateAuthorityData: []byte(k.CACertificate),
	}
	config.AuthInfos["kubelet-bootstrap"] = &clientcmdapi.AuthInfo{Token: token}
	config.Contexts["bootstrap"] = &clientcmdapi.Context{Cluster: "cluster", AuthInfo: "kubelet-bootstrap"}
	config.CurrentContext = "bootstrap"
	return clientcmd.Write(*config)
}

// kubeletInputs are stage's files under kubernetesDir, rendered before any is
// written.
type kubeletInputs struct {
	files []fileutil.NewFile
	pods  []fileutil.NewFile
	env   []byte
}

// workerValues are the placeholder values of a worker named name: the floor's
// and the static pods'.
func workerValues(name string, k Kubernetes) map[string]string {
	return map[string]string{
		nodeservices.NodeNamePlaceholder: name,
		nodeservices.PodCIDRPlaceholder:  k.PodCIDR,
	}
}

// renderKubelet renders the inputs of a kubelet registering as name at
// address.
func renderKubelet(rootDir string, k Kubernetes, token, name, address string) (*kubeletInputs, error) {
	config, err := kubeletConfig(k)
	if err != nil {
		return nil, err
	}
	bootstrap, err := bootstrapKubeconfig(k, token)
	if err != nil {
		return nil, err
	}
	pods, err := staticPods(rootDir, workerValues(name, k))
	if err != nil {
		return nil, err
	}
	return &kubeletInputs{
		files: []fileutil.NewFile{
			{Name: filepath.Base(bootstrapKubeconfigPath), Data: bootstrap, Mode: 0o600},
			{Name: filepath.Base(kubeletConfigPath), Data: config, Mode: 0o644},
		},
		pods: pods,
		env:  []byte("NODE_NAME=" + name + "\nNODE_IP=" + address + "\n"),
	}, nil
}

// write writes kubelet.env last: a kubelet unit that requires it starts only
// once the rest exists.
func (in *kubeletInputs) write(rootDir string) error {
	dir := filepath.Join(rootDir, kubernetesDir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := fileutil.WriteNewDir(dir, 0o755, in.files); err != nil {
		return err
	}
	if err := fileutil.WriteNewDir(filepath.Join(rootDir, staticPodPath), 0o755, in.pods); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(rootDir, kubeletEnvPath), in.env, 0o644)
}
