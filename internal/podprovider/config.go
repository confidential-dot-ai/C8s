// Package podprovider schedules one explicitly opted-in Kubernetes Pod into
// one Cloud CVM, retaining the signed launch intent until deletion completes.
package podprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	// Annotation opts a Pod into the provider and also labels its virtual node.
	Annotation          = "confidential.ai/pod-cvm"
	ownerLabel          = "confidential.ai/pod-cvm-provider"
	finalizer           = "confidential.ai/pod-cvm"
	endpointsAnnotation = "confidential.ai/pod-cvm-endpoints"
	maxFile             = 1 << 20
)

// Config is trusted operator configuration. Paths name mounted files, never
// tenant annotations. LoadConfig reads their contents once before registration.
type Config struct {
	ProviderID          string   `json:"providerID"`
	NodeName            string   `json:"nodeName"`
	Namespace           string   `json:"namespace"`
	CloudURL            string   `json:"cloudURL"`
	CloudTokenFile      string   `json:"cloudTokenFile"`
	Image               string   `json:"image"`
	ImageManifestFile   string   `json:"imageManifestFile"`
	LaunchKeyFile       string   `json:"launchKeyFile"`
	ServerAddress       string   `json:"serverAddress"`
	ServerPublicKeyFile string   `json:"serverPublicKeyFile"`
	WorkloadsFile       string   `json:"workloadsFile"`
	ClusterID           string   `json:"clusterID"`
	Size                string   `json:"size"`
	Location            string   `json:"location"`
	VCPUs               int64    `json:"vCPUs"`
	MemoryMiB           int64    `json:"memoryMiB"`
	ReservedMemoryMiB   int64    `json:"reservedMemoryMiB"`
	MaxPods             int64    `json:"maxPods"`
	MeshPeers           []string `json:"meshPeers,omitempty"`
	PublicIP            string   `json:"publicIP,omitempty"`

	token     string
	key       *ecdsa.PrivateKey
	pub       string
	serverPub string
	manifest  []byte
	workloads string
	image     launchconfig.Image
}

// LoadConfig strictly loads trusted configuration and verifies that its launch
// inputs satisfy the same contract the guest and bundle CLI enforce.
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
	for _, p := range []*string{&cfg.CloudTokenFile, &cfg.ImageManifestFile, &cfg.LaunchKeyFile, &cfg.ServerPublicKeyFile, &cfg.WorkloadsFile} {
		if *p == "" {
			return nil, errors.New("pod CVM provider requires token, image manifest, launch key, server public key and workloads files")
		}
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	if err := cfg.loadTrust(); err != nil {
		return nil, err
	}
	probe := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{UID: types.UID("configuration-check"), Namespace: "default", Name: "configuration-check"}, Spec: corev1.PodSpec{AutomountServiceAccountToken: new(false), Containers: []corev1.Container{{Name: "app", Image: "example.invalid/app@sha256:" + strings.Repeat("a", 64)}}}}
	if _, err := cfg.launch(probe); err != nil {
		return nil, fmt.Errorf("pod CVM launch configuration: %w", err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	for _, s := range []string{c.ProviderID, c.NodeName, c.Namespace} {
		if len(validation.IsDNS1123Label(s)) != 0 {
			return errors.New("providerID, nodeName and namespace must be DNS labels")
		}
	}
	u, err := url.Parse(c.CloudURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("cloudURL must be an HTTPS origin without credentials, query or path")
	}
	c.CloudURL = strings.TrimRight(c.CloudURL, "/")
	if !strings.Contains(c.Image, "@") || strings.ContainsAny(c.Image, "/ \t\r\n") || strings.Count(c.Image, "@") != 1 {
		return errors.New("image must pin a Cloud catalog family@version")
	}
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
	if c.VCPUs < 1 || c.VCPUs > 1024 || c.MemoryMiB < 1 || c.MemoryMiB > 1<<22 || c.ReservedMemoryMiB < 1 || c.ReservedMemoryMiB >= c.MemoryMiB || c.MaxPods < 1 || c.MaxPods > 10000 {
		return errors.New("invalid provider capacity: require bounded positive vCPUs, memoryMiB, reservedMemoryMiB below memoryMiB, and maxPods")
	}
	return launchconfig.ValidateIPv4(c.ServerAddress, true)
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
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read provider input %s: %w", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > maxFile {
		return nil, errors.New("provider input must contain 1..1048576 bytes")
	}
	return b, nil
}

func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("expected exactly one JSON document")
	}
	return nil
}
