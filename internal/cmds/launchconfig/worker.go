package launchconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/netip"

	clientcmdv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Kubernetes names the cluster a worker joins, whose control plane runs
// outside the worker and outside C8s's trust: every field is public and
// cluster-wide, so one signed document serves every node of a pool. The
// node's name is not here: c8s node-credential derives it from the node key,
// and CDS signs it into the join token.
type Kubernetes struct {
	// APIServer is the hostname of the cluster's API server, on 443.
	APIServer string `yaml:"apiServer" json:"api_server"`
	// CACertificate is the PEM of the one CA the API server chains to. The
	// kubelet trusts only it, and the credential plugin refuses any other.
	CACertificate string `yaml:"caCertificate" json:"ca_certificate"`
	// ClusterDNS is the cluster DNS Service's address, which the kubelet
	// gives pods as their resolver and the mesh admits on the resolver port.
	ClusterDNS string `yaml:"clusterDNS" json:"cluster_dns"`
	// ClusterDomain defaults to cluster.local.
	ClusterDomain string `yaml:"clusterDomain,omitempty" json:"cluster_domain,omitempty"`
	// PodCIDR and ServiceCIDR are the cluster's ranges: a destination inside
	// them is a mesh member.
	PodCIDR     string `yaml:"podCIDR" json:"pod_cidr"`
	ServiceCIDR string `yaml:"serviceCIDR" json:"service_cidr"`
}

const defaultClusterDomain = "cluster.local"

func (k *Kubernetes) validate() error {
	if err := ValidateHostname(k.APIServer); err != nil {
		return fmt.Errorf("kubernetes.apiServer: %w", err)
	}
	if _, err := k.CA(); err != nil {
		return err
	}
	dns, err := netip.ParseAddr(k.ClusterDNS)
	if err != nil || !dns.Is4() || !dns.IsGlobalUnicast() {
		return fmt.Errorf("kubernetes.clusterDNS must be a unicast IPv4 address")
	}
	if k.ClusterDomain == "" {
		k.ClusterDomain = defaultClusterDomain
	}
	if err := ValidateHostname(k.ClusterDomain); err != nil {
		return fmt.Errorf("kubernetes.clusterDomain: %w", err)
	}
	pods, err := clusterRange("kubernetes.podCIDR", k.PodCIDR)
	if err != nil {
		return err
	}
	services, err := clusterRange("kubernetes.serviceCIDR", k.ServiceCIDR)
	if err != nil {
		return err
	}
	if pods.Overlaps(services) {
		return fmt.Errorf("kubernetes.podCIDR and kubernetes.serviceCIDR overlap")
	}
	if !services.Contains(dns) {
		return fmt.Errorf("kubernetes.clusterDNS must be inside kubernetes.serviceCIDR")
	}
	return nil
}

func clusterRange(field, raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 {
		return netip.Prefix{}, fmt.Errorf("%s must be an IPv4 network in CIDR form, /8 or longer", field)
	}
	return prefix, nil
}

// ClusterRanges are the pod and Service ranges, in that order.
func (k *Kubernetes) ClusterRanges() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix(k.PodCIDR), netip.MustParsePrefix(k.ServiceCIDR)}
}

// CA parses the one CA certificate, refusing anything else in the PEM.
func (k *Kubernetes) CA() (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(k.CACertificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("kubernetes.caCertificate must be exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("kubernetes.caCertificate: %w", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, fmt.Errorf("kubernetes.caCertificate is not a CA certificate")
	}
	return cert, nil
}

// CASHA256 is the hex SHA-256 of the CA certificate's DER, as the credential
// plugin pins it.
func (k *Kubernetes) CASHA256() string {
	cert, err := k.CA()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// The worker's kubelet files. The kubelet's own configuration is baked and
// measured (/usr/lib/c8s/worker-runtime/kubelet.yaml); these carry only what
// the signed document names, so neither the host nor the control plane can
// choose the kubelet's authentication, authorization or debugging handlers.
const (
	WorkerDir                 = "/run/c8s-worker"
	workerBootstrapKubeconfig = WorkerDir + "/bootstrap-kubeconfig"
	workerCA                  = WorkerDir + "/ca.crt"
	workerKubeletDropIn       = WorkerDir + "/kubelet.conf.d/50-cluster.conf"
	// credentialPlugin is the measured binary the bootstrap kubeconfig runs.
	credentialPlugin = "/usr/local/bin/c8s"
)

// bootstrapKubeconfig is the kubelet's bootstrap kubeconfig: the signed
// server and CA, and c8s node-credential as its user, pinned to the same
// server, CA and CDS. With no certificate yet, or an expired one, the kubelet
// runs the plugin, which attests this node to CDS for a minutes-long token.
func bootstrapKubeconfig(doc *Document) ([]byte, error) {
	k := doc.Kubernetes
	args := []string{
		"node-credential",
		"--cds-url=" + doc.CDSURL(),
		"--image-policy-file=" + Dir + "/cds.json",
		"--attestation-api-url=" + DefaultAttestationAPIURL,
		"--api-server=" + k.APIServer,
		"--api-ca-sha256=" + k.CASHA256(),
	}
	if doc.Image.HasRuntimeRegister() {
		args = append(args, "--measured-policies-file="+armtls.NodeJournal)
	}
	config := clientcmdv1.Config{
		APIVersion: "v1",
		Kind:       "Config",
		Clusters: []clientcmdv1.NamedCluster{{Name: "cluster", Cluster: clientcmdv1.Cluster{
			Server:                   "https://" + k.APIServer,
			CertificateAuthorityData: []byte(k.CACertificate),
		}}},
		AuthInfos: []clientcmdv1.NamedAuthInfo{{Name: "node", AuthInfo: clientcmdv1.AuthInfo{
			Exec: &clientcmdv1.ExecConfig{
				APIVersion:         "client.authentication.k8s.io/v1",
				Command:            credentialPlugin,
				Args:               args,
				ProvideClusterInfo: true,
				InteractiveMode:    clientcmdv1.NeverExecInteractiveMode,
			},
		}}},
		Contexts:       []clientcmdv1.NamedContext{{Name: "node", Context: clientcmdv1.Context{Cluster: "cluster", AuthInfo: "node"}}},
		CurrentContext: "node",
	}
	return yaml.Marshal(config)
}

// kubeletDropIn is the cluster's part of the kubelet configuration, merged
// over the baked file through the kubelet's --config-dir.
func kubeletDropIn(doc *Document) ([]byte, error) {
	k := doc.Kubernetes
	return yaml.Marshal(map[string]any{
		"apiVersion":    "kubelet.config.k8s.io/v1beta1",
		"kind":          "KubeletConfiguration",
		"clusterDNS":    []string{k.ClusterDNS},
		"clusterDomain": k.ClusterDomain,
		// The API server reaches the kubelet with a client certificate the
		// cluster CA signed.
		"authentication": map[string]any{"x509": map[string]any{"clientCAFile": workerCA}},
	})
}

func workerOutputs(doc *Document) ([]outputFile, error) {
	kubeconfig, err := bootstrapKubeconfig(doc)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap kubeconfig: %w", err)
	}
	dropIn, err := kubeletDropIn(doc)
	if err != nil {
		return nil, fmt.Errorf("encode kubelet configuration: %w", err)
	}
	return []outputFile{
		{workerBootstrapKubeconfig, kubeconfig},
		{workerCA, []byte(doc.Kubernetes.CACertificate)},
		{workerKubeletDropIn, dropIn},
	}, nil
}
