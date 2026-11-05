// Package acceptance drives the live Cloud acceptance scenarios for the Pod
// guest image: it launches guests through the Cloud API with signed launch
// documents, assigns generic guests through the guest assignment API, and
// retains every Cloud side effect in a private ledger until cleanup completes.
package acceptance

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
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const maxFile = 1 << 20

// Config is the trusted launcher configuration. Paths name private files the
// run wrote itself; LoadConfig reads their contents once per launcher.
type Config struct {
	ProviderID          string   `json:"providerID"`
	CloudURL            string   `json:"cloudURL"`
	CloudTokenFile      string   `json:"cloudTokenFile"`
	Image               string   `json:"image"`
	ImageManifestFile   string   `json:"imageManifestFile"`
	LaunchKeyFile       string   `json:"launchKeyFile"`
	ServerAddress       string   `json:"serverAddress"`
	ServerPublicKeyFile string   `json:"serverPublicKeyFile"`
	CDSAddress          string   `json:"cdsAddress"`
	CDSImagePolicyFile  string   `json:"cdsImagePolicyFile"`
	CDSPinDecreeFile    string   `json:"cdsPinDecreeFile,omitempty"`
	WorkloadsFile       string   `json:"workloadsFile"`
	ClusterID           string   `json:"clusterID"`
	Size                string   `json:"size"`
	Location            string   `json:"location"`
	VCPUs               int64    `json:"vCPUs"`
	MemoryMiB           int64    `json:"memoryMiB"`
	MeshPeers           []string `json:"meshPeers,omitempty"`
	PublicIP            string   `json:"publicIP,omitempty"`

	token     string
	key       *ecdsa.PrivateKey
	pub       string
	serverPub string
	manifest  []byte
	workloads string
	image     launchconfig.Image
	cds       launchconfig.CDS
}

// LoadConfig strictly loads the launcher configuration and verifies that its
// launch inputs satisfy the same contract the guest and bundle CLI enforce.
func LoadConfig(path string) (*Config, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("pod CVM launcher configuration: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	for _, p := range []*string{&cfg.CloudTokenFile, &cfg.ImageManifestFile, &cfg.LaunchKeyFile, &cfg.ServerPublicKeyFile, &cfg.CDSImagePolicyFile, &cfg.WorkloadsFile} {
		if *p == "" {
			return nil, errors.New("pod CVM launcher requires token, image manifest, launch key, server public key, CDS image policy and workloads files")
		}
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	if cfg.CDSPinDecreeFile != "" && !filepath.IsAbs(cfg.CDSPinDecreeFile) {
		cfg.CDSPinDecreeFile = filepath.Join(filepath.Dir(path), cfg.CDSPinDecreeFile)
	}
	if err := cfg.loadTrust(); err != nil {
		return nil, err
	}
	probe := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{UID: types.UID("configuration-check"), Namespace: "default", Name: "configuration-check"}, Spec: corev1.PodSpec{AutomountServiceAccountToken: new(false), Containers: []corev1.Container{{Name: "app", Image: "example.invalid/app@sha256:" + strings.Repeat("a", 64)}}}}
	if _, err := cfg.launch(probe); err != nil {
		return nil, fmt.Errorf("pod CVM launch configuration: %w", err)
	}
	if _, err := cfg.genericLaunch(identityKey(cfg.ProviderID, "configuration-generic-check")); err != nil {
		return nil, fmt.Errorf("generic Pod CVM configuration: %w", err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if len(validation.IsDNS1123Label(c.ProviderID)) != 0 {
		return errors.New("providerID must be a DNS label")
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
	if c.VCPUs < 1 || c.VCPUs > 1024 || c.MemoryMiB < 1 || c.MemoryMiB > 1<<22 {
		return errors.New("invalid guest shape: require bounded positive vCPUs and memoryMiB")
	}
	if err := launchconfig.ValidateIPv4(c.ServerAddress, true); err != nil {
		return err
	}
	_, err = launchconfig.CDS{Address: c.CDSAddress}.Port()
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
		return errors.New("launch key must be an ECDSA P-256 private key")
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
	pins, err := refvalues.Parse(cdsPolicy)
	if err != nil {
		return fmt.Errorf("CDS image policy: %w", err)
	}
	launchFile, err := cmdsutil.CDSLaunchFile(pins)
	if err != nil {
		return fmt.Errorf("CDS image policy: %w", err)
	}
	c.cds = launchconfig.CDS{Address: c.CDSAddress, Measurements: string(cdsPolicy)}
	if c.CDSPinDecreeFile != "" {
		c.cds, err = launchconfig.CDSFromPinDecree(launchFile, c.CDSPinDecreeFile, c.CDSAddress)
		if err != nil {
			return fmt.Errorf("CDS pin decree: %w", err)
		}
	}
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
		return errors.New("guest image must support Pod runtime measurements")
	}
	return nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read launcher input %s: %w", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > maxFile {
		return nil, errors.New("launcher input must contain 1..1048576 bytes")
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
