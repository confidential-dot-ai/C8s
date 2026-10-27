package launchconfig

import (
	"fmt"
	"net"
	"net/url"
	"regexp"

	"github.com/confidential-dot-ai/attestation-go/remote"
)

// Managed is the section a managed cluster's c8s-launch/v2 document adds. It
// names the Cluster API Machine the node is, the trust policy it was launched
// under, and the management enrollment service that releases its RKE2 role
// material once it has checked this node's evidence. It holds nothing secret.
type Managed struct {
	Pool        string `yaml:"pool" json:"pool"`
	MachineName string `yaml:"machineName" json:"machine_name"`
	MachineUID  string `yaml:"machineUID" json:"machine_uid"`
	Policy      Policy `yaml:"policy" json:"policy"`
	// BootstrapDigest is "sha256:<hex>" of the role material enrollment
	// releases for this Machine. The node refuses any other bytes, so the
	// launch signer, not only the enrollment service, decides what it runs.
	BootstrapDigest string     `yaml:"bootstrapDigest" json:"bootstrap_digest"`
	Enrollment      Enrollment `yaml:"enrollment" json:"enrollment"`
}

// Policy names the cluster's trust policy by digest and epoch.
type Policy struct {
	Digest string `yaml:"digest" json:"digest"`
	Epoch  int64  `yaml:"epoch" json:"epoch"`
}

// Enrollment is where the node enrolls, and what it must find there: the
// service's armTLS evidence has to match one of Management, image and launch
// key together, before the node sends anything.
type Enrollment struct {
	URL        string          `yaml:"url" json:"url"`
	Management []ManagementPin `yaml:"management" json:"management"`
}

// ManagementPin is one management image the node accepts: its measurements
// and the launch key bound into its evidence (RTMR[3] on TDX, HOST_DATA on
// SNP), so a management image booted by anyone else does not match.
type ManagementPin struct {
	Image     `yaml:",inline"`
	LaunchKey string `yaml:"launchKey" json:"launch_key"`
}

const maxManagementPins = 8

var (
	sha256DigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	machineUIDRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func (m *Managed) validate(d *Document) error {
	if !dnsLabel(m.Pool) {
		return fmt.Errorf("managed.pool must be an RFC1123 label")
	}
	// The node registers under its Machine's name, which is how Cluster API
	// and its control plane provider find it.
	if m.MachineName != d.Node.Name {
		return fmt.Errorf("managed.machineName must equal node.name")
	}
	if !machineUIDRE.MatchString(m.MachineUID) {
		return fmt.Errorf("managed.machineUID must be a lowercase UUID")
	}
	if !sha256DigestRE.MatchString(m.Policy.Digest) || m.Policy.Epoch < 1 {
		return fmt.Errorf("managed.policy needs a sha256:<hex> digest and an epoch of at least 1")
	}
	if !sha256DigestRE.MatchString(m.BootstrapDigest) {
		return fmt.Errorf("managed.bootstrapDigest must be sha256:<hex>")
	}
	if err := validateEnrollmentURL(m.Enrollment.URL); err != nil {
		return fmt.Errorf("managed.enrollment.url: %w", err)
	}
	if n := len(m.Enrollment.Management); n == 0 || n > maxManagementPins {
		return fmt.Errorf("managed.enrollment.management must list 1..%d images", maxManagementPins)
	}
	for i, pin := range m.Enrollment.Management {
		if err := pin.validate(); err != nil {
			return fmt.Errorf("managed.enrollment.management[%d]: %w", i, err)
		}
	}
	return nil
}

func (p ManagementPin) validate() error {
	platform, ok := p.platform()
	if !ok {
		return fmt.Errorf("platform must be tdx or snp")
	}
	if !registerHex(p.Measurement) {
		return fmt.Errorf("measurement must be 96 lowercase hex characters")
	}
	if err := platform.validateRegisters(p.RTMRs); err != nil {
		return err
	}
	if _, err := parseLaunchKey(p.LaunchKey); err != nil {
		return fmt.Errorf("launchKey: %w", err)
	}
	return nil
}

// validateEnrollmentURL accepts exactly https://<unicast IPv4>:<port>. The
// node resolves no name before it has checked who answers.
func validateEnrollmentURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must be https://<ipv4>:<port>")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || !portNumber(port) || "https://"+net.JoinHostPort(host, port) != raw {
		return fmt.Errorf("must be https://<ipv4>:<port>")
	}
	return ValidateIPv4(host, true)
}

// ManagementPolicy is the evidence policy the node holds its enrollment
// service to: any listed management image, each with its launch key.
func (m *Managed) ManagementPolicy() remote.Policy {
	var policy remote.Policy
	for i, pin := range m.Enrollment.Management {
		entry := remote.ImagePin{
			Name:   fmt.Sprintf("management-%d", i),
			Digest: mustDecodeHex(pin.Measurement),
			Anchor: []byte(pin.LaunchKey),
		}
		if len(pin.RTMRs) > 0 {
			entry.Registers = make(map[int][]byte, len(pin.RTMRs))
			for idx, digest := range pin.RTMRs {
				entry.Registers[idx] = mustDecodeHex(digest)
			}
		}
		policy.Images = append(policy.Images, entry)
	}
	return policy
}
