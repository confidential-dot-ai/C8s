// Package objectcustody binds CDS recovery keys to one measured SNP custodian.
// The approved boot chain must cover its executable and forbid host-selected
// code. A generic firmware measurement and HOST_DATA alone are insufficient.
package objectcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"maps"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
)

const SchemaVersion = "c8s-cds-custody/v1"

// AuthorityPlaceholder occurs exactly once, as the CDS recovery authority.
// Only the separate CDS launch substitutes it; custody always boots its original bytes.
const AuthorityPlaceholder = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type Parameters struct {
	GuestSVN uint32
	TCB      uint64
}

type Config struct {
	document   []byte
	template   []byte
	images     []remote.ImagePin
	ownerDER   []byte
	parameters Parameters
	snpMinTCB  teetypes.SnpTcb
}

type wire struct {
	SchemaVersion string   `yaml:"schemaVersion"`
	CDSTemplate   string   `yaml:"cdsTemplate"`
	CDSImages     []string `yaml:"cdsImages"`
	OwnerClientCA string   `yaml:"ownerClientCA"`
	Derivation    struct {
		GuestSVN *uint32 `yaml:"guestSVN"`
		TCB      *uint64 `yaml:"tcb"`
	} `yaml:"derivation"`
}

// Parse checks public configuration; the caller must authenticate Document()
// against the custodian's native self-report before deriving or serving keys.
func Parse(document []byte) (*Config, error) {
	var input wire
	if err := yamlutil.Decode(
		document,
		&input,
	); err != nil {
		return nil, err
	}
	if input.SchemaVersion != SchemaVersion || input.Derivation.GuestSVN == nil ||
		input.Derivation.TCB == nil || *input.Derivation.TCB == 0 {
		return nil, errors.New("object custody: version and fixed SNP derivation parameters required")
	}
	template := []byte(input.CDSTemplate)
	cds, err := cdsconfig.Parse(template)
	if err != nil || cds.ObjectState == nil ||
		base64.StdEncoding.EncodeToString(cds.ObjectState.RecoveryAuthority) != AuthorityPlaceholder ||
		bytes.Count(
			template,
			[]byte(AuthorityPlaceholder),
		) != 1 {
		return nil, errors.New("object custody: CDS object-state template must contain its unique authority placeholder")
	}
	images, err := parseImages(input.CDSImages)
	if err != nil {
		return nil, err
	}
	owner, err := parseOwnerCA([]byte(input.OwnerClientCA))
	if err != nil {
		return nil, err
	}
	return &Config{
		document:  bytes.Clone(document),
		template:  template,
		images:    images,
		ownerDER:  bytes.Clone(owner.Raw),
		snpMinTCB: cds.ObjectState.SNPMinTCB,
		parameters: Parameters{
			GuestSVN: *input.Derivation.GuestSVN,
			TCB:      *input.Derivation.TCB,
		},
	}, nil
}

func parseImages(documents []string) ([]remote.ImagePin, error) {
	if len(documents) == 0 || len(documents) > 2 {
		return nil, errors.New("object custody: one image document per approved SNP or TDX family required")
	}
	families := make(map[teetypes.Family]bool)
	var images []remote.ImagePin
	for _, document := range documents {
		values, err := refvalues.Parse([]byte(document))
		if err != nil || families[values.Family] || len(images)+len(values.Images) > 64 {
			return nil, errors.New("object custody: invalid, repeated or oversized image policy")
		}
		families[values.Family] = true
		for _, image := range values.Images {
			if image.Anchor != nil || image.LaunchFile != nil || image.LaunchFileDigest != nil ||
				image.AcceptExtension != nil || bytes.Equal(
				image.Digest,
				make(
					[]byte,
					refvalues.DigestSize,
				),
			) {
				return nil, errors.New("object custody: image policy must contain only fixed image identities")
			}
			// RTMR3 commits the completed launch, including the derived authority.
			// Complete binds it through LaunchFile after replacing the placeholder.
			if values.Family == teetypes.FamilyTDX && (len(image.Registers) != 2 ||
				len(image.Registers[1]) != refvalues.DigestSize || len(image.Registers[2]) != refvalues.DigestSize) {
				return nil, errors.New("object custody: TDX identity must pin only stable registers 1 and 2; register 3 is bound by the completed launch")
			}
			images = append(
				images,
				image,
			)
		}
	}
	return images, nil
}

func parseOwnerCA(document []byte) (*x509.Certificate, error) {
	if !bytes.HasPrefix(
		bytes.TrimSpace(document),
		[]byte("-----BEGIN CERTIFICATE-----"),
	) {
		return nil, errors.New("object custody: public owner CA certificate required")
	}
	block, rest := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("object custody: exactly one public owner CA certificate required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("object custody: owner certificate must be a self-signed CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, errors.New("object custody: owner CA must be valid for client authentication")
	}
	return cert, nil
}

func (c *Config) Document() []byte           { return bytes.Clone(c.document) }
func (c *Config) Parameters() Parameters     { return c.parameters }
func (c *Config) SNPMinTCB() teetypes.SnpTcb { return c.snpMinTCB }

func (c *Config) OwnerCA() *x509.Certificate {
	cert, _ := x509.ParseCertificate(bytes.Clone(c.ownerDER))
	return cert
}

// Complete changes only the placeholder bytes and binds every approved image
// to that exact CDS launch. Returned configuration and pins belong to the caller.
// LaunchFile requires the bare launch binding: TDX RTMR3 or SNP HOST_DATA.
func (c *Config) Complete(authority ed25519.PublicKey) ([]byte, *cdsconfig.Config, []remote.ImagePin, error) {
	if c == nil || len(c.document) == 0 || len(authority) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(authority) == AuthorityPlaceholder {
		return nil, nil, nil, errors.New("object custody: derived public authority required")
	}
	launch := bytes.Replace(
		c.template,
		[]byte(AuthorityPlaceholder),
		[]byte(base64.StdEncoding.EncodeToString(authority)),
		1,
	)
	cds, err := cdsconfig.Parse(launch)
	if err != nil || !bytes.Equal(
		cds.ObjectState.RecoveryAuthority,
		authority,
	) {
		return nil, nil, nil, errors.New("object custody: completed CDS launch is invalid")
	}
	images := make(
		[]remote.ImagePin,
		len(c.images),
	)
	for index, image := range c.images {
		image.Digest = bytes.Clone(image.Digest)
		image.Registers = maps.Clone(image.Registers)
		for register, value := range image.Registers {
			image.Registers[register] = bytes.Clone(value)
		}
		image.LaunchFile = bytes.Clone(launch)
		images[index] = image
	}
	return launch, cds, images, nil
}

type Material struct {
	Signer   ed25519.PrivateKey
	StateKey []byte
}

func (m *Material) Clear() {
	clear(m.Signer)
	clear(m.StateKey)
	*m = Material{}
}
