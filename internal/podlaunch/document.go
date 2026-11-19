// Package podlaunch authenticates and stages the launch document of a pod CVM:
// a measured guest that runs one assigned pod under a standalone kubelet. The
// document is signed with the pod launch key, whose public half the initrd
// staged off the launch disk and bound into RTMR[3]. It names no pod: the
// guest boots generic and takes one signed assignment (Assign).
//
// This is the pod half of the launch configuration package the worker model
// removed. Server and agent roles, RKE2 settings and the server identity are
// gone with it: a pod CVM document names no cluster server.
package podlaunch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

const (
	SchemaVersion            = "c8s-launch/v2"
	DefaultAttestationAPIURL = "http://127.0.0.1:8400"
	// Dir holds the root-only artifacts Stage writes for the guest services.
	Dir               = "/run/confos/launch"
	DefaultStagedPath = Dir + "/config.json"
	MaxDocumentSize   = 1024 * 1024
	maxSignatureSize  = 4096
	maxLaunchKeySize  = 8192
)

// Role names what a launch document boots. Pod is the only one left.
type Role string

// Pod runs one static pod under a standalone kubelet.
const Pod Role = "pod"

// Document is the signed launch.yaml wire contract of a pod CVM.
type Document struct {
	SchemaVersion string `yaml:"schemaVersion" json:"schema_version"`
	ClusterID     string `yaml:"clusterID" json:"cluster_id"`
	Role          Role   `yaml:"role" json:"role"`
	Image         Image  `yaml:"image" json:"image"`
	Node          Node   `yaml:"node" json:"node"`
	// PodOperatorPublicKey is the pod launch key: the exact PEM bytes the
	// launch bound and assignments are signed with.
	PodOperatorPublicKey string `yaml:"podOperatorPublicKey" json:"pod_operator_public_key"`
	// CDS is the confidential data service the guest's credential broker
	// reaches, outside the pod network.
	CDS cmdsutil.CDS `yaml:"cds" json:"cds"`
}

// Image pins this boot's complete software identity. Platform names which
// imagePlatform owns the rest: Measurement is the launch digest every platform
// has, and RTMRs is the register map only some of them populate. RTMR[0] varies
// by VM shape and RTMR[3] binds the launch key, so neither belongs in the pins.
type Image struct {
	Platform    string         `yaml:"platform" json:"platform"`
	Measurement string         `yaml:"measurement" json:"measurement"`
	RTMRs       map[int]string `yaml:"rtmrs,omitempty" json:"rtmrs,omitempty"`
}

// imagePlatform names the TEE family a launch tag selects.
type imagePlatform struct {
	family teetypes.Family
	// runtimeRegister is set when the platform has a register the guest can
	// extend after launch (RTMR[3]), into which a pod measures its workloads.
	runtimeRegister bool
}

var imagePlatforms = map[string]imagePlatform{
	"tdx": {family: teetypes.FamilyTDX, runtimeRegister: true},
	"snp": {family: teetypes.FamilySNP},
}

// validateRegisters refuses a register map that is not the set this platform's
// guests are identified by.
func (p imagePlatform) validateRegisters(rtmrs map[int]string) error {
	identifying, _ := armtls.ImageRegisters(p.family)
	if len(rtmrs) != len(identifying) {
		return fmt.Errorf("a %s image pins %s", p.family, registerRule(identifying))
	}
	for _, index := range identifying {
		if !registerHex(rtmrs[index]) {
			return fmt.Errorf("image.rtmrs[%d] must be 96 lowercase hex characters", index)
		}
	}
	return nil
}

func registerRule(identifying []int) string {
	if len(identifying) == 0 {
		return "no RTMRs"
	}
	names := make([]string, 0, len(identifying))
	for _, index := range identifying {
		names = append(names, fmt.Sprintf("RTMR[%d]", index))
	}
	return "exactly " + strings.Join(names, " and ")
}

// platform resolves the document's launch tag. Callers reach it only after
// validate, which rejects any tag without an entry here.
func (i Image) platform() (imagePlatform, bool) {
	p, ok := imagePlatforms[i.Platform]
	return p, ok
}

// HasRuntimeRegister reports whether the image's platform can measure
// workloads after launch.
func (i Image) HasRuntimeRegister() bool {
	p, _ := i.platform()
	return p.runtimeRegister
}

// Node names the pod CVM; the standalone kubelet registers under it.
type Node struct {
	Name string `yaml:"name" json:"name"`
}

// Parse strictly validates the offline launch document. Guest callers must
// use Verify first; Parse alone provides no authentication.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := yamlutil.Decode(data, &doc); err != nil {
		return nil, fmt.Errorf("launch configuration: %w", err)
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (d *Document) validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if _, err := d.CDS.Parse(); err != nil {
		return err
	}
	if d.CDS.Chain != "" {
		if _, err := cdschain.ParsePin(d.CDS.Chain); err != nil {
			return fmt.Errorf("cds.chain: %w", err)
		}
	}
	if !dnsLabel(d.ClusterID) {
		return fmt.Errorf("clusterID must be an RFC1123 label")
	}
	if !dnsLabel(d.Node.Name) {
		return fmt.Errorf("node.name must be an RFC1123 label")
	}
	if d.Role != Pod {
		return fmt.Errorf("role must be pod")
	}
	platform, ok := d.Image.platform()
	if !ok {
		return fmt.Errorf("image.platform must be tdx or snp")
	}
	if !registerHex(d.Image.Measurement) {
		return fmt.Errorf("image.measurement must be 96 lowercase hex characters")
	}
	if err := platform.validateRegisters(d.Image.RTMRs); err != nil {
		return err
	}
	if !platform.runtimeRegister {
		return fmt.Errorf("%s requires a platform with a runtime register to measure its workloads; %s has none", d.Role, d.Image.Platform)
	}
	if _, err := parseLaunchKey(d.PodOperatorPublicKey); err != nil {
		return fmt.Errorf("podOperatorPublicKey: %w", err)
	}
	return nil
}

func (d *Document) authorizeKey(pub []byte) error {
	if !bytes.Equal(pub, []byte(d.PodOperatorPublicKey)) {
		return fmt.Errorf("%s launch key does not match podOperatorPublicKey bytes", d.Role)
	}
	return nil
}

func parseLaunchKey(raw string) (*ecdsa.PublicKey, error) {
	if len(raw) > maxLaunchKeySize {
		return nil, fmt.Errorf("launch public key is too large")
	}
	return runtimemeasure.ParsePublicKeyPEM([]byte(raw))
}

func dnsLabel(s string) bool { return len(validation.IsDNS1123Label(s)) == 0 }

func registerHex(s string) bool {
	if len(s) != sha512.Size384*2 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func mustDecodeHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a regular file containing 1..%d bytes", path, limit)
	}
	data, err := readutil.ReadAll(f, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s exceeded the bounded read", path)
	}
	return data, nil
}

// LoadStaged reads a root-owned boot artifact produced by Stage. It is not an
// authentication API for host input; only the fixed staged path is trusted.
func LoadStaged(path string) (*Document, error) {
	// JSON may expand a YAML string byte to a six-byte Unicode escape.
	data, err := readBounded(path, 6*MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode staged launch configuration: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("staged launch configuration contains trailing data")
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}
