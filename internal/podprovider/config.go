// Package podprovider schedules one explicitly opted-in Kubernetes Pod into
// one Cloud CVM, retaining the signed launch intent until deletion completes.
package podprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	// Annotation opts a Pod into the provider and also labels its virtual node.
	Annotation          = "confidential.ai/pod-cvm"
	ownerLabel          = "confidential.ai/pod-cvm-provider"
	finalizer           = "confidential.ai/pod-cvm"
	endpointsAnnotation = "confidential.ai/pod-cvm-endpoints"
	// appEndpointPrefix names the Cloud ingress rule of a declared
	// containerPort: app-<port>.
	appEndpointPrefix = "app-"
)

// Config is trusted operator configuration. Paths name mounted files, never
// tenant annotations. LoadConfig reads their contents once before registration.
type Config struct {
	ProviderID                 string   `json:"providerID"`
	NodeName                   string   `json:"nodeName"`
	Namespace                  string   `json:"namespace"`
	CloudURL                   string   `json:"cloudURL"`
	CloudTokenFile             string   `json:"cloudTokenFile"`
	Image                      string   `json:"image"`
	ImageManifestFile          string   `json:"imageManifestFile"`
	LaunchKeyFile              string   `json:"launchKeyFile"`
	ServerAddress              string   `json:"serverAddress"`
	ServerPublicKeyFile        string   `json:"serverPublicKeyFile"`
	CDSAddress                 string   `json:"cdsAddress"`
	CDSImagePolicyFile         string   `json:"cdsImagePolicyFile"`
	WorkloadsFile              string   `json:"workloadsFile"`
	ClusterID                  string   `json:"clusterID"`
	Size                       string   `json:"size"`
	Location                   string   `json:"location"`
	VCPUs                      int64    `json:"vCPUs"`
	MemoryMiB                  int64    `json:"memoryMiB"`
	ReservedMemoryMiB          int64    `json:"reservedMemoryMiB"`
	MaxPods                    int64    `json:"maxPods"`
	MeshPeers                  []string `json:"meshPeers,omitempty"`
	PublicIP                   string   `json:"publicIP,omitempty"`
	VerificationTimeoutSeconds int64    `json:"verificationTimeoutSeconds,omitempty"`

	token     string
	key       *ecdsa.PrivateKey
	pub       string
	serverPub string
	manifest  []byte
	workloads string
	image     launchconfig.Image
	cds       launchconfig.CDS
}

// LoadConfig loads the trusted configuration and the launch inputs it names.
func LoadConfig(path string) (*Config, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("pod CVM provider configuration: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	for _, p := range []*string{&cfg.CloudTokenFile, &cfg.ImageManifestFile, &cfg.LaunchKeyFile, &cfg.ServerPublicKeyFile, &cfg.CDSImagePolicyFile, &cfg.WorkloadsFile} {
		if *p == "" {
			return nil, errors.New("pod CVM provider requires token, image manifest, launch key, server public key, CDS image policy and workloads files")
		}
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	if err := cfg.loadTrust(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validate applies the documented defaults and the operator-settable bounds of
// the verification deadline.
func (c *Config) validate() error {
	if c.VerificationTimeoutSeconds == 0 {
		c.VerificationTimeoutSeconds = defaultVerificationTimeoutSeconds
	}
	if !validVerificationTimeout(c.VerificationTimeoutSeconds) {
		return errors.New("verificationTimeoutSeconds must be between 30 and 86400")
	}
	c.CloudURL = strings.TrimRight(c.CloudURL, "/")
	if c.Size == "" || c.Location == "" || c.ClusterID == "" {
		return errors.New("size, location and clusterID are required")
	}
	if c.PublicIP == "" {
		c.PublicIP = "shared"
	}
	if c.PublicIP != "shared" && c.PublicIP != "dedicated" {
		return errors.New("publicIP must be shared or dedicated")
	}
	if c.ReservedMemoryMiB == 0 {
		c.ReservedMemoryMiB = 1024
	}
	if err := launchconfig.ValidateIPv4(c.ServerAddress, true); err != nil {
		return err
	}
	_, err := launchconfig.CDS{Address: c.CDSAddress}.Port()
	return err
}

func (c *Config) loadTrust() error {
	token, err := readFile(c.CloudTokenFile)
	if err != nil {
		return err
	}
	c.token = strings.TrimSpace(string(token))
	if c.token == "" || strings.ContainsAny(c.token, " \t\r\n") {
		return errors.New("cloud token file must hold one bearer token")
	}
	key, err := readFile(c.LaunchKeyFile)
	if err != nil {
		return err
	}
	c.key, err = certutil.ParseECPrivateKey(key)
	if err != nil || c.key.Curve != elliptic.P256() {
		return errors.New("provider launch key must be an ECDSA P-256 private key")
	}
	pub, err := x509.MarshalPKIXPublicKey(&c.key.PublicKey)
	if err != nil {
		return err
	}
	c.pub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	server, err := readFile(c.ServerPublicKeyFile)
	if err != nil {
		return err
	}
	c.serverPub = string(server)
	cdsPolicy, err := readFile(c.CDSImagePolicyFile)
	if err != nil {
		return err
	}
	// The policy must bind the CDS image to its exact launch file, or the
	// guest could not authenticate the CDS it polls.
	pins, err := refvalues.Parse(cdsPolicy)
	if err != nil {
		return fmt.Errorf("CDS image policy: %w", err)
	}
	if _, err := cmdsutil.CDSLaunchFile(pins); err != nil {
		return fmt.Errorf("CDS image policy: %w", err)
	}
	c.cds = launchconfig.CDS{Address: c.CDSAddress, Measurements: string(cdsPolicy)}
	workloads, err := readFile(c.WorkloadsFile)
	if err != nil {
		return err
	}
	c.workloads = string(workloads)
	c.manifest, err = readFile(c.ImageManifestFile)
	if err != nil {
		return err
	}
	identity, err := runtimemeasure.LoadImageManifest(c.ImageManifestFile)
	if err != nil {
		return err
	}
	vcpus := int(c.VCPUs)
	if identity.Family() == teetypes.FamilyTDX {
		vcpus = 0
	}
	c.image, err = launchconfig.ImageFromManifest(c.ImageManifestFile, vcpus)
	if err != nil {
		return err
	}
	if !c.image.HasRuntimeRegister() {
		return errors.New("provider image must support Pod runtime measurements")
	}
	return nil
}

func readFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read provider input %s: %w", path, err)
	}
	return b, nil
}

func decode(b []byte, out any) error {
	return json.Unmarshal(b, out)
}
