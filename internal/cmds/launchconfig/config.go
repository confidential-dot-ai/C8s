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
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
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
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	SchemaVersion            = "c8s-launch/v1"
	DefaultAttestationAPIURL = "http://127.0.0.1:8400"
	// Dir holds the root-only artifacts Stage writes for the node services.
	Dir               = "/run/confos/launch"
	DefaultStagedPath = Dir + "/config.json"
	MaxDocumentSize   = 1024 * 1024
	maxSignatureSize  = 4096
	maxLaunchKeySize  = 8192
	maxAgentKeys      = 128
	maxMirrors        = 8
	defaultTLSSAN     = "c8s.local"
)

// Role selects the services started for this boot, without changing its image.
type Role string

const (
	Server Role = "server"
	Agent  Role = "agent"
	// Pod runs one static pod under a standalone kubelet; RKE2 never starts.
	Pod Role = "pod"
	// Worker joins a cluster whose control plane runs elsewhere, on the pod
	// role's runtime with a joined kubelet; RKE2 never starts.
	Worker Role = "worker"
)

// Valid reports whether r is a role this image can boot.
func (r Role) Valid() bool {
	_, ok := roles[r]
	return ok
}

// presence says whether a role's document must, may or must not carry a
// field. The zero value is the strict one.
type presence int

const (
	forbidden presence = iota
	optional
	required
)

// roleRules keeps each role's document rules in one place, so validate,
// authorizeKey and referenceValues ask the role instead of testing for it
// inline. Adding a role means adding an entry, not new branches; every entry
// sets every field.
type roleRules struct {
	// joinsCluster requires rke2.agentToken; a role that joins no cluster
	// must carry neither token. optional is not meaningful here.
	joinsCluster bool
	serverToken  presence // rke2.serverToken, distinct from rke2.agentToken
	agentKeys    presence // agentOperatorPublicKeys
	podKey       presence // podOperatorPublicKey
	pod          presence // the pod section, which then requires workloads
	// measuresWorkloads requires a platform with a runtime register: the
	// role measures what it runs after launch, and without the register no
	// evidence could carry those measurements.
	measuresWorkloads bool
	// namesServer requires server.address in the signed document; otherwise
	// it is checked only when present.
	namesServer bool
	// stagedAddress requires the staged document to carry a server address,
	// which Stage resolves for a server that omitted it.
	stagedAddress bool
	router        bool // may carry a router block
	// node is the node section: a per-node document names its node, and a
	// worker's per-pool one names none, since its name comes from its key.
	node       presence
	kubernetes presence // the kubernetes section a worker joins
	// ownLaunchKey authorizes the exact server.operatorPublicKey bytes;
	// otherwise the launch key must be listed in agentOperatorPublicKeys and
	// differ from the server's. A podKey authorizes its own exact bytes.
	ownLaunchKey bool
}

var roles = map[Role]roleRules{
	Server: {
		joinsCluster:  true,
		serverToken:   required,
		agentKeys:     optional,
		podKey:        forbidden,
		pod:           forbidden,
		namesServer:   false,
		stagedAddress: true,
		router:        true,
		ownLaunchKey:  true,
		node:          required,
		kubernetes:    forbidden,
	},
	Agent: {
		joinsCluster:  true,
		serverToken:   forbidden,
		agentKeys:     required,
		podKey:        forbidden,
		pod:           forbidden,
		namesServer:   true,
		stagedAddress: true,
		router:        false,
		ownLaunchKey:  false,
		node:          required,
		kubernetes:    forbidden,
	},
	Pod: {
		joinsCluster:      false,
		serverToken:       forbidden,
		agentKeys:         forbidden,
		podKey:            required,
		pod:               required,
		measuresWorkloads: true,
		namesServer:       true,
		stagedAddress:     true,
		router:            false,
		ownLaunchKey:      false,
		node:              required,
		kubernetes:        forbidden,
	},
	// A worker's launch key is listed in agentOperatorPublicKeys, as an
	// agent's is: CDS admits the same keys to its node issuer.
	Worker: {
		joinsCluster:  false,
		serverToken:   forbidden,
		agentKeys:     required,
		podKey:        forbidden,
		pod:           forbidden,
		namesServer:   true,
		stagedAddress: true,
		router:        false,
		ownLaunchKey:  false,
		node:          forbidden,
		kubernetes:    required,
	},
}

// rules resolves the document's role. Callers reach it only after validate,
// which rejects any role without an entry in roles.
func (d *Document) rules() roleRules { return roles[d.Role] }

// Document is the signed launch.yaml wire contract. All secrets are boot
// inputs; agent documents must never carry the control-plane server token.
type Document struct {
	SchemaVersion           string       `yaml:"schemaVersion" json:"schema_version"`
	ClusterID               string       `yaml:"clusterID" json:"cluster_id"`
	Role                    Role         `yaml:"role" json:"role"`
	Image                   Image        `yaml:"image" json:"image"`
	Node                    Node         `yaml:"node,omitempty" json:"node"`
	RKE2                    RKE2         `yaml:"rke2" json:"rke2"`
	Server                  ServerConfig `yaml:"server" json:"server"`
	AgentOperatorPublicKeys []string     `yaml:"agentOperatorPublicKeys" json:"agent_operator_public_keys"`
	// PodOperatorPublicKey verifies pod documents; Server still pins CDS.
	PodOperatorPublicKey string `yaml:"podOperatorPublicKey,omitempty" json:"pod_operator_public_key,omitempty"`
	TLSSAN               string `yaml:"tlsSAN,omitempty" json:"tls_san"`

	// Workloads is an optional strict c8s.allowlist/v1 JSON document. Keeping
	// its existing wire schema avoids an independent YAML policy language.
	Workloads string `yaml:"workloads,omitempty" json:"workloads,omitempty"`

	// PodImagePolicy authorizes Pod workload issuance, separately from node
	// peer trust. Only a signed server document may supply this JSON policy.
	PodImagePolicy string `yaml:"podImagePolicy,omitempty" json:"pod_image_policy,omitempty"`

	// Router is the server's front door. A baked image cannot know it at
	// build time, so the signed launch file carries it.
	Router *Router `yaml:"router,omitempty" json:"router,omitempty"`

	// RegistryMirrors maps a registry host to the http endpoint containerd
	// pulls it through; Stage writes it as RKE2's registries.yaml. Only http:
	// the document carries no CA, and a cache on a private address has no
	// public certificate. Image references stay digest-pinned, so a mirror
	// cannot change what a node runs.
	RegistryMirrors map[string]string `yaml:"registryMirrors,omitempty" json:"registry_mirrors,omitempty"`

	// Pod is the one static pod a pod-role boot runs; forbidden otherwise.
	Pod *PodSpec `yaml:"pod,omitempty" json:"pod,omitempty"`

	// Kubernetes is the cluster a worker joins; forbidden otherwise.
	Kubernetes *Kubernetes `yaml:"kubernetes,omitempty" json:"kubernetes,omitempty"`

	serverTokenPresent bool
}

// Router selects the router's public hostnames and front-door limits. All
// fields are optional; non-empty Hostnames switches the front door to ACME.
// The route manifest, not this block, names every backend.
type Router struct {
	Hostnames        []string `yaml:"hostnames,omitempty" json:"hostnames,omitempty"`
	ACMEEmail        string   `yaml:"acmeEmail,omitempty" json:"acme_email,omitempty"`
	ACMEDirectoryURL string   `yaml:"acmeDirectoryURL,omitempty" json:"acme_directory_url,omitempty"`
	// MaxRequestBodyBytes caps an application request body on the public
	// listener; 0 keeps DefaultMaxRequestBodyBytes.
	MaxRequestBodyBytes int64 `yaml:"maxRequestBodyBytes,omitempty" json:"max_request_body_bytes,omitempty"`
}

// DefaultMaxRequestBodyBytes is the router's application request body cap
// when the launch document sets none: nginx's own default, 1 MiB.
const DefaultMaxRequestBodyBytes = 1 << 20

// RequestBodyLimit is the application request body cap the router applies.
func (r Router) RequestBodyLimit() int64 {
	if r.MaxRequestBodyBytes == 0 {
		return DefaultMaxRequestBodyBytes
	}
	return r.MaxRequestBodyBytes
}

// ValidateHostname accepts a lowercase DNS hostname: no IP, no wildcard.
func ValidateHostname(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("%q exceeds DNS name length", name)
	}
	if name == "" || net.ParseIP(name) != nil {
		return fmt.Errorf("%q must be a lowercase DNS hostname", name)
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabel(label) {
			return fmt.Errorf("%q must be a lowercase DNS hostname", name)
		}
	}
	return nil
}

const maxRouterHostnames = 100 // the ACME CA's SAN limit per certificate

func (r *Router) validate() error {
	if len(r.Hostnames) > maxRouterHostnames {
		return fmt.Errorf("router.hostnames lists more than %d names", maxRouterHostnames)
	}
	seen := make(map[string]bool, len(r.Hostnames))
	for _, name := range r.Hostnames {
		if err := ValidateHostname(name); err != nil {
			return fmt.Errorf("router.hostnames: %w", err)
		}
		if seen[name] {
			return fmt.Errorf("router.hostnames lists %q twice", name)
		}
		seen[name] = true
	}
	if r.MaxRequestBodyBytes < 0 {
		return fmt.Errorf("router.maxRequestBodyBytes must be a positive number of bytes")
	}
	if len(r.Hostnames) == 0 && (r.ACMEEmail != "" || r.ACMEDirectoryURL != "") {
		return fmt.Errorf("router.acmeEmail and router.acmeDirectoryURL require router.hostnames")
	}
	if r.ACMEEmail != "" {
		addr, err := mail.ParseAddress(r.ACMEEmail)
		if err != nil || addr.Address != r.ACMEEmail || addr.Name != "" {
			return fmt.Errorf("router.acmeEmail must be a bare email address")
		}
	}
	if r.ACMEDirectoryURL != "" {
		u, err := url.Parse(r.ACMEDirectoryURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.String() != r.ACMEDirectoryURL || strings.ContainsAny(r.ACMEDirectoryURL, " \t\r\n") {
			return fmt.Errorf("router.acmeDirectoryURL must be an https URL")
		}
	}
	return nil
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
	// runtimeRegister is set when the platform has a register the guest can
	// extend after launch (RTMR[3]), into which a pod measures its workloads.
	runtimeRegister bool
	// validateRegisters rejects a register map that does not match what this
	// platform measures. Its error names the platform's own rule.
	validateRegisters func(rtmrs map[int]string) error
}

var imagePlatforms = map[string]imagePlatform{
	"tdx": {
		family:          teetypes.FamilyTDX,
		runtimeRegister: true,
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

// HasRuntimeRegister reports whether the image's platform can measure
// workloads after launch.
func (i Image) HasRuntimeRegister() bool {
	p, _ := i.platform()
	return p.runtimeRegister
}

type Node struct {
	Name       string `yaml:"name" json:"name"`
	IP         string `yaml:"ip,omitempty" json:"ip,omitempty"`
	ExternalIP string `yaml:"externalIP,omitempty" json:"external_ip,omitempty"`
}

type RKE2 struct {
	ServerToken string `yaml:"serverToken,omitempty" json:"server_token,omitempty"`
	AgentToken  string `yaml:"agentToken" json:"agent_token"`
	// NodePassword is this node's RKE2 node password, random per node and
	// carried only in its own document. /etc/rancher is per-boot scratch, so
	// without it RKE2 makes a new password at every boot and the server
	// refuses a rebooted node's name. Per node, so holding the shared agent
	// token, or one node's document, does not open another node's name.
	NodePassword string `yaml:"nodePassword,omitempty" json:"node_password,omitempty"`
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
	// MeasuredPoliciesFile is the node's measured-policy journal, as
	// cred-release's --measured-policies-file. Empty replays none.
	MeasuredPoliciesFile string
	// ProviderIDPath is the worker's unsigned provider ID beside the signed
	// document (ParseProviderID); a worker requires it, other roles refuse it.
	ProviderIDPath string
	RootDir        string
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
	measured, err := loadMeasuredIdentity(ctx, string(platform.Family()), api, cfg.MeasuredPoliciesFile)
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

var tokenRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d *Document) validate() error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion must be %s", SchemaVersion)
	}
	if !dnsLabel(d.ClusterID) {
		return fmt.Errorf("clusterID must be an RFC1123 label")
	}
	if !d.Role.Valid() {
		return fmt.Errorf("role must be server, agent, pod or worker")
	}
	rules := d.rules()
	switch rules.node {
	case required:
		if !dnsLabel(d.Node.Name) {
			return fmt.Errorf("node.name must be an RFC1123 label")
		}
	case forbidden:
		if d.Node != (Node{}) {
			return fmt.Errorf("%s must not carry a node section: its name comes from its node key", d.Role)
		}
	}
	switch rules.kubernetes {
	case required:
		if d.Kubernetes == nil {
			return fmt.Errorf("%s requires a kubernetes section", d.Role)
		}
		if err := d.Kubernetes.validate(); err != nil {
			return err
		}
	case forbidden:
		if d.Kubernetes != nil {
			return fmt.Errorf("kubernetes section requires role worker")
		}
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
	if rules.measuresWorkloads && !platform.runtimeRegister {
		return fmt.Errorf("%s requires a platform with a runtime register to measure its workloads; %s has none", d.Role, d.Image.Platform)
	}
	if d.Server.Address != "" || rules.namesServer {
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
	if !rules.joinsCluster {
		if d.RKE2.AgentToken != "" || d.RKE2.ServerToken != "" || d.serverTokenPresent {
			return fmt.Errorf("%s must not carry rke2 tokens", d.Role)
		}
	} else if !tokenRE.MatchString(d.RKE2.AgentToken) {
		return fmt.Errorf("rke2.agentToken must be 64 lowercase hex characters")
	}
	switch rules.serverToken {
	case required:
		if !tokenRE.MatchString(d.RKE2.ServerToken) {
			return fmt.Errorf("%s requires a 64-character lowercase hex rke2.serverToken", d.Role)
		}
		if d.RKE2.ServerToken == d.RKE2.AgentToken {
			return fmt.Errorf("server and agent tokens must differ")
		}
	case forbidden:
		if d.RKE2.ServerToken != "" || d.serverTokenPresent {
			return fmt.Errorf("%s must not carry rke2.serverToken", d.Role)
		}
	}
	if p := d.RKE2.NodePassword; p != "" {
		if !rules.joinsCluster {
			return fmt.Errorf("%s must not carry rke2.nodePassword", d.Role)
		}
		if !tokenRE.MatchString(p) {
			return fmt.Errorf("rke2.nodePassword must be 64 lowercase hex characters")
		}
		if p == d.RKE2.AgentToken || p == d.RKE2.ServerToken {
			return fmt.Errorf("rke2.nodePassword must differ from the join tokens")
		}
	}
	server, err := parseLaunchKey(d.Server.OperatorPublicKey)
	if err != nil {
		return fmt.Errorf("server.operatorPublicKey: %w", err)
	}
	switch rules.podKey {
	case required:
		podKey, err := parseLaunchKey(d.PodOperatorPublicKey)
		if err != nil {
			return fmt.Errorf("podOperatorPublicKey: %w", err)
		}
		if podKey.Equal(server) {
			return fmt.Errorf("pod and server public keys must be distinct")
		}
	case forbidden:
		if d.PodOperatorPublicKey != "" {
			return fmt.Errorf("podOperatorPublicKey requires role pod")
		}
	}
	if len(d.AgentOperatorPublicKeys) > maxAgentKeys {
		return fmt.Errorf("too many agent operator keys")
	}
	switch rules.agentKeys {
	case required:
		if len(d.AgentOperatorPublicKeys) == 0 {
			return fmt.Errorf("%s requires agentOperatorPublicKeys", d.Role)
		}
	case forbidden:
		if len(d.AgentOperatorPublicKeys) != 0 {
			return fmt.Errorf("%s must not carry agentOperatorPublicKeys", d.Role)
		}
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
	if err := d.validatePodImagePolicy(seen); err != nil {
		return err
	}
	if d.TLSSAN == "" {
		d.TLSSAN = defaultTLSSAN
	}
	if err := ValidateHostname(d.TLSSAN); err != nil {
		return fmt.Errorf("tlsSAN: %w", err)
	}
	if d.Router != nil {
		if !rules.router {
			return fmt.Errorf("router is server-only")
		}
		if err := d.Router.validate(); err != nil {
			return err
		}
	}
	switch rules.pod {
	case required:
		if d.Pod == nil {
			return fmt.Errorf("%s requires a pod section", d.Role)
		}
		if d.Workloads == "" {
			return fmt.Errorf("%s requires workloads as its base allowlist", d.Role)
		}
		if err := d.Pod.validate(); err != nil {
			return err
		}
	case forbidden:
		if d.Pod != nil {
			return fmt.Errorf("pod section requires role pod")
		}
	}
	if d.Workloads != "" {
		if !json.Valid([]byte(d.Workloads)) {
			return fmt.Errorf("workloads must contain one valid JSON document")
		}
		workloads, err := allowlist.ParseJSON([]byte(d.Workloads))
		if err != nil {
			return fmt.Errorf("workloads: %w", err)
		}
		if rules.pod == required && len(workloads.Workloads) == 0 {
			return fmt.Errorf("%s requires workloads with at least one workload as its cold-boot base", d.Role)
		}
	}
	return validateRegistryMirrors(d.RegistryMirrors)
}

// validateRegistryMirrors accepts registry hosts (a lowercase DNS name with an
// optional port) mapped to http origins with a unicast IPv4 host.
func validateRegistryMirrors(mirrors map[string]string) error {
	if len(mirrors) > maxMirrors {
		return fmt.Errorf("registryMirrors has more than %d entries", maxMirrors)
	}
	for registry, endpoint := range mirrors {
		host, port, hasPort := strings.Cut(registry, ":")
		if ValidateHostname(host) != nil || (hasPort && !portNumber(port)) {
			return fmt.Errorf("registryMirrors: %q must be a lowercase DNS hostname with an optional port", registry)
		}
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "http" || u.Host == "" || endpoint != "http://"+u.Host {
			return fmt.Errorf("registryMirrors: %q must map to an endpoint of the form http://host[:port]", registry)
		}
		host, port, hasPort = strings.Cut(u.Host, ":")
		if hasPort && !portNumber(port) {
			return fmt.Errorf("registryMirrors: %q endpoint port must be 1..65535", registry)
		}
		if err := ValidateIPv4(host, true); err != nil {
			return fmt.Errorf("registryMirrors: %q endpoint host %w", registry, err)
		}
	}
	return nil
}

// portNumber accepts a canonical decimal TCP port.
func portNumber(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && strconv.Itoa(p) == s && len(validation.IsValidPortNum(p)) == 0
}

func (d *Document) validatePodImagePolicy(nodeKeys []*ecdsa.PublicKey) error {
	if d.PodImagePolicy == "" {
		return nil
	}
	if d.Role != Server {
		return fmt.Errorf("podImagePolicy is server-only")
	}
	pins, err := workloadclaims.ParsePodImagePolicy([]byte(d.PodImagePolicy))
	if err != nil {
		return fmt.Errorf("podImagePolicy: %w", err)
	}
	for _, pin := range pins.Images {
		key, err := parseLaunchKey(string(pin.Anchor))
		if err != nil {
			return fmt.Errorf("podImagePolicy: %w", err)
		}
		for _, nodeKey := range nodeKeys {
			if key.Equal(nodeKey) {
				return fmt.Errorf("pod launch keys must differ from server and agent launch keys")
			}
		}
	}
	return nil
}

func (d *Document) authorizeKey(pub []byte, key *ecdsa.PublicKey) error {
	if d.rules().podKey == required {
		if !bytes.Equal(pub, []byte(d.PodOperatorPublicKey)) {
			return fmt.Errorf("%s launch key does not match podOperatorPublicKey bytes", d.Role)
		}
		return nil
	}
	server, err := parseLaunchKey(d.Server.OperatorPublicKey)
	if err != nil {
		return fmt.Errorf("parse server operator public key: %w", err)
	}
	if d.rules().ownLaunchKey {
		if !bytes.Equal(pub, []byte(d.Server.OperatorPublicKey)) {
			return fmt.Errorf("%s launch key does not match server.operatorPublicKey bytes", d.Role)
		}
		return nil
	}
	if key.Equal(server) {
		return fmt.Errorf("%s must use a different launch key from its server", d.Role)
	}
	for _, agent := range d.AgentOperatorPublicKeys {
		if bytes.Equal(pub, []byte(agent)) {
			return nil
		}
	}
	return fmt.Errorf("this %s's measured launch key is not in agentOperatorPublicKeys", d.Role)
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
	type identity struct{ name, publicKey string }
	// The first pin is always the CDS server, independently of this boot's key.
	keys := []identity{{"server", d.Server.OperatorPublicKey}}
	for i, pub := range d.AgentOperatorPublicKeys {
		keys = append(keys, identity{fmt.Sprintf("agent-%d", i+1), pub})
	}
	if d.PodOperatorPublicKey != "" {
		keys = append(keys, identity{"pod", d.PodOperatorPublicKey})
	}
	for _, key := range keys {
		entry := remote.ImagePin{Name: key.name, Digest: mustDecodeHex(d.Image.Measurement), Anchor: []byte(key.publicKey)}
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

// cdsPort is the image's fixed CDS node port.
const cdsPort = 30808

// CDSURL is derived from the signed server address and the image's fixed port.
func (d *Document) CDSURL() string {
	return "https://" + net.JoinHostPort(d.Server.Address, strconv.Itoa(cdsPort))
}

// CDSAddrPort is that same endpoint as an address and port, which is what a
// pod ruleset names as a destination. A signed address that is not one fails
// here rather than in the node's packet rules.
func (d *Document) CDSAddrPort() (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(d.Server.Address)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("staged server address %q: %w", d.Server.Address, err)
	}
	return netip.AddrPortFrom(addr, cdsPort), nil
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
	if doc.Server.Address == "" && doc.rules().stagedAddress {
		return nil, fmt.Errorf("staged configuration must contain a resolved server address")
	}
	return &doc, nil
}
