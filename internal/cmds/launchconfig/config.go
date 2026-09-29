// Package launchconfig authenticates and stages the boot configuration of a
// measured node image. It is the only source of server/agent selection.
// Each cluster needs its own distinct server/agent launch keys: ClusterID
// names a cluster, while the launch keys establish its remote trust boundary.
package launchconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const (
	SchemaVersion            = "c8s-launch/v2"
	DefaultAttestationAPIURL = "http://127.0.0.1:8400"
	// Dir holds the root-only artifacts Stage writes for the node services.
	Dir               = "/run/confos/launch"
	DefaultStagedPath = Dir + "/config.json"
	MaxDocumentSize   = 1024 * 1024
	maxSignatureSize  = 4096
	maxAgentKeys      = 128
	defaultTLSSAN     = "c8s.local"
)

// Role selects the services started for this boot, without changing its image.
type Role string

const (
	Server Role = "server"
	Agent  Role = "agent"
)

// Document is the public signed launch.yaml wire contract. Join credentials
// are generated inside the guest and never accepted from launch media: the
// server mints its agent token in RAM and RKE2 generates its own server
// token, so no field here carries a secret.
type Document struct {
	SchemaVersion           string       `yaml:"schemaVersion" json:"schema_version"`
	ClusterID               string       `yaml:"clusterID" json:"cluster_id"`
	Role                    Role         `yaml:"role" json:"role"`
	Image                   Image        `yaml:"image" json:"image"`
	Node                    Node         `yaml:"node" json:"node"`
	Server                  ServerConfig `yaml:"server" json:"server"`
	AgentOperatorPublicKeys []string     `yaml:"agentOperatorPublicKeys" json:"agent_operator_public_keys"`
	TLSSAN                  string       `yaml:"tlsSAN,omitempty" json:"tls_san"`
	// Workloads is an optional strict c8s.allowlist/v1 JSON document. Keeping
	// its existing wire schema avoids an independent YAML policy language.
	Workloads string `yaml:"workloads,omitempty" json:"workloads,omitempty"`
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

// imagePlatform keeps each TEE's register rules in one place, so the shared
// verify, validate and policy paths ask the platform instead of testing for
// "tdx" inline. Adding a platform means adding an entry, not new branches.
type imagePlatform struct {
	family teetypes.Family
	// validateRegisters rejects a register map that does not match what this
	// platform measures. Its error names the platform's own rule.
	validateRegisters func(rtmrs map[int]string) error
}

var imagePlatforms = map[string]imagePlatform{
	"tdx": {
		family: teetypes.FamilyTDX,
		validateRegisters: func(rtmrs map[int]string) error {
			if len(rtmrs) != 2 || !registerHex(rtmrs[1]) || !registerHex(rtmrs[2]) {
				return fmt.Errorf("TDX image must pin exactly RTMR[1] and RTMR[2]")
			}
			return nil
		},
	},
	"snp": {
		family: teetypes.FamilySNP,
		validateRegisters: func(rtmrs map[int]string) error {
			if len(rtmrs) != 0 {
				return fmt.Errorf("SNP image cannot carry RTMR pins")
			}
			return nil
		},
	},
}

// platform resolves the document's launch tag. Callers reach it only after
// validate, which rejects any tag without an entry here.
func (i Image) platform() (imagePlatform, bool) {
	p, ok := imagePlatforms[i.Platform]
	return p, ok
}

type Node struct {
	Name       string `yaml:"name" json:"name"`
	IP         string `yaml:"ip,omitempty" json:"ip,omitempty"`
	ExternalIP string `yaml:"externalIP,omitempty" json:"external_ip,omitempty"`
}

type ServerConfig struct {
	// Address may be omitted only for a server; Stage resolves its own IP.
	Address string `yaml:"address,omitempty" json:"address"`
	// Exact PEM bytes are hardware-bound. Equivalent PEM encodings of one
	// key are still one authorization identity, not two different roles.
	OperatorPublicKey string `yaml:"operatorPublicKey" json:"operator_public_key"`
}

// Config selects trusted local facilities and launch files. RootDir rebases
// fixed output paths for tests; it is not exposed as a command-line flag.
type Config struct {
	Platform          string
	AttestationAPIURL string
	DocumentPath      string
	SignaturePath     string
	RootDir           string
}

var loadMeasuredIdentity = credrelease.LoadMeasuredIdentity

// Verified is created only after signature, image and role authorization pass.
// Its fields are private so staging cannot accidentally consume an unverified
// Document supplied by a caller.
type Verified struct {
	document    Document
	operatorPub []byte
	pins        refvalues.ReferenceValues
	cdsPins     refvalues.ReferenceValues
}

// Verify checks the signature before parsing host input and compares all image
// pins against one verified, fresh self-report. A keyless boot fails closed.
func Verify(ctx context.Context, cfg Config) (*Verified, error) {
	platform := teetypes.NormalizePlatform(cfg.Platform)
	if platform != teetypes.PlatformTDX && platform != teetypes.PlatformSNP {
		return nil, fmt.Errorf("platform must be tdx or snp")
	}
	if cfg.DocumentPath == "" || cfg.SignaturePath == "" {
		return nil, fmt.Errorf("both --config and --signature are required")
	}
	data, err := readBounded(cfg.DocumentPath, MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	signature, err := readBounded(cfg.SignaturePath, maxSignatureSize)
	if err != nil {
		return nil, err
	}
	api := cfg.AttestationAPIURL
	if api == "" {
		api = DefaultAttestationAPIURL
	}
	// credrelease compares against the verified report's family ("sev-snp",
	// "tdx"), not the launch tag ("snp", "tdx").
	measured, err := loadMeasuredIdentity(ctx, string(platform.Family()), api)
	if err != nil {
		return nil, fmt.Errorf("verify this boot's identity: %w", err)
	}
	if measured.OperatorKeyErr != nil {
		return nil, fmt.Errorf("launch configuration requires a measured operator key: %w", measured.OperatorKeyErr)
	}
	pub := measured.OperatorKey
	key, err := parseLaunchKey(string(pub))
	if err != nil {
		return nil, fmt.Errorf("measured launch key: %w", err)
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{key}, data, string(signature)); err != nil {
		return nil, fmt.Errorf("launch configuration signature: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if teetypes.NormalizePlatform(doc.Image.Platform) != platform {
		return nil, fmt.Errorf("launch image platform does not match this boot")
	}
	if measured.Image == nil {
		return nil, fmt.Errorf("verified self-report contains no image identity")
	}
	digests := measured.Image.LaunchDigests()
	if len(digests) == 0 {
		return nil, fmt.Errorf("verified self-report contains no launch digests")
	}
	digest := digests[0].Digest
	if !bytes.Equal(mustDecodeHex(doc.Image.Measurement), digest[:]) {
		return nil, fmt.Errorf("launch image measurement does not match this boot")
	}
	rtmrs := measured.Image.RTMRs()
	for i, value := range doc.Image.RTMRs {
		observed, ok := rtmrs[i]
		if !ok || !bytes.Equal(mustDecodeHex(value), observed[:]) {
			return nil, fmt.Errorf("launch image RTMR[%d] does not match this boot", i)
		}
	}
	if err := doc.authorizeKey(pub, key); err != nil {
		return nil, err
	}
	pins, err := doc.referenceValues()
	if err != nil {
		return nil, err
	}
	return &Verified{
		document: *doc, operatorPub: pub, pins: pins,
		cdsPins: refvalues.ReferenceValues{Family: pins.Family, Images: pins.Images[:1]},
	}, nil
}

func (d *Document) validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if !dnsLabel(d.ClusterID) {
		return fmt.Errorf("clusterID must be an RFC1123 label")
	}
	if !dnsLabel(d.Node.Name) {
		return fmt.Errorf("node.name must be an RFC1123 label")
	}
	if d.Role != Server && d.Role != Agent {
		return fmt.Errorf("role must be server or agent")
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
	if d.Server.Address != "" || d.Role == Agent {
		if err := ValidateIPv4(d.Server.Address, true); err != nil {
			return fmt.Errorf("server.address: %w", err)
		}
	}
	if d.Node.IP != "" {
		if err := ValidateIPv4(d.Node.IP, false); err != nil {
			return fmt.Errorf("node.ip: %w", err)
		}
		if d.Node.IP == "0.0.0.0" {
			d.Node.IP = ""
		}
	}
	if d.Node.ExternalIP != "" {
		if err := ValidateIPv4(d.Node.ExternalIP, true); err != nil {
			return fmt.Errorf("node.externalIP: %w", err)
		}
	}
	server, err := parseLaunchKey(d.Server.OperatorPublicKey)
	if err != nil {
		return fmt.Errorf("server.operatorPublicKey: %w", err)
	}
	if len(d.AgentOperatorPublicKeys) > maxAgentKeys {
		return fmt.Errorf("too many agent operator keys")
	}
	if d.Role == Agent && len(d.AgentOperatorPublicKeys) == 0 {
		return fmt.Errorf("agent requires agentOperatorPublicKeys")
	}
	seen := []*ecdsa.PublicKey{server}
	for _, raw := range d.AgentOperatorPublicKeys {
		key, err := parseLaunchKey(raw)
		if err != nil {
			return fmt.Errorf("agentOperatorPublicKeys: %w", err)
		}
		for _, previous := range seen {
			if key.Equal(previous) {
				return fmt.Errorf("server and agent public keys must be distinct and nonduplicated")
			}
		}
		seen = append(seen, key)
	}
	if d.TLSSAN == "" {
		d.TLSSAN = defaultTLSSAN
	}
	if len(d.TLSSAN) > 253 {
		return fmt.Errorf("tlsSAN exceeds DNS name length")
	}
	for _, label := range strings.Split(d.TLSSAN, ".") {
		if !dnsLabel(label) {
			return fmt.Errorf("tlsSAN must be a lowercase DNS hostname")
		}
	}
	if d.Workloads != "" {
		if !json.Valid([]byte(d.Workloads)) {
			return fmt.Errorf("workloads must contain one valid JSON document")
		}
		if _, err := allowlist.ParseJSON([]byte(d.Workloads)); err != nil {
			return fmt.Errorf("workloads: %w", err)
		}
	}
	return nil
}

func (d *Document) authorizeKey(pub []byte, key *ecdsa.PublicKey) error {
	server, err := parseLaunchKey(d.Server.OperatorPublicKey)
	if err != nil {
		return fmt.Errorf("parse server operator public key: %w", err)
	}
	if d.Role == Server {
		if !bytes.Equal(pub, []byte(d.Server.OperatorPublicKey)) {
			return fmt.Errorf("server launch key does not match server.operatorPublicKey bytes")
		}
		return nil
	}
	if key.Equal(server) {
		return fmt.Errorf("agent must use a different launch key from its server")
	}
	for _, agent := range d.AgentOperatorPublicKeys {
		if bytes.Equal(pub, []byte(agent)) {
			return nil
		}
	}
	return fmt.Errorf("this agent's measured launch key is not in agentOperatorPublicKeys")
}

func parseLaunchKey(raw string) (*ecdsa.PublicKey, error) {
	if len(raw) > 8192 {
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

// ValidateIPv4 accepts an IPv4 address; routable additionally requires
// global unicast, so loopback and unspecified addresses cannot be published.
func ValidateIPv4(raw string, routable bool) error {
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("must be an IPv4 address")
	}
	if routable && !addr.IsGlobalUnicast() {
		return fmt.Errorf("must be a unicast IPv4 address")
	}
	return nil
}

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

func (d *Document) referenceValues() (refvalues.ReferenceValues, error) {
	platform, ok := d.Image.platform()
	if !ok {
		return refvalues.ReferenceValues{}, fmt.Errorf("image.platform must be tdx or snp")
	}
	pins := refvalues.ReferenceValues{Family: platform.family}
	keys := append([]string{d.Server.OperatorPublicKey}, d.AgentOperatorPublicKeys...)
	for i, pub := range keys {
		name := "server"
		if i > 0 {
			name = fmt.Sprintf("agent-%d", i)
		}
		entry := remote.ImagePin{Name: name, Digest: mustDecodeHex(d.Image.Measurement), Anchor: []byte(pub)}
		if len(d.Image.RTMRs) > 0 {
			entry.Registers = make(map[int][]byte, len(d.Image.RTMRs))
			for idx, digest := range d.Image.RTMRs {
				entry.Registers[idx] = mustDecodeHex(digest)
			}
		}
		pins.Images = append(pins.Images, entry)
	}
	// Use the shared parser as a final schema check on the emitted policy.
	data, err := refvalues.Format(pins)
	if err != nil {
		return refvalues.ReferenceValues{}, err
	}
	return refvalues.Parse(data)
}

// CDSURL is derived from the signed server address and the image's fixed port.
func (d *Document) CDSURL() string { return "https://" + d.Server.Address + ":30808" }

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
	if doc.Server.Address == "" {
		return nil, fmt.Errorf("staged configuration must contain a resolved server address")
	}
	return &doc, nil
}
