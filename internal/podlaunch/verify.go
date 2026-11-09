package podlaunch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/launchbinding"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Config selects trusted local facilities and launch files. RootDir rebases
// fixed output paths for tests; it is not exposed as a command-line flag.
type Config struct {
	Platform          string
	AttestationAPIURL string
	DocumentPath      string
	SignaturePath     string
	// MeasuredPoliciesFile is the guest's RTMR[3] journal. Empty replays none.
	MeasuredPoliciesFile string
	RootDir              string
}

var loadMeasuredIdentity = launchbinding.LoadMeasuredIdentity

// Verified is created only after signature, image and key authorization pass.
// Its fields are private so staging cannot accidentally consume an unverified
// Document supplied by a caller.
type Verified struct {
	document    Document
	operatorPub []byte
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
	// launchbinding compares against the verified report's family ("sev-snp",
	// "tdx"), not the launch tag ("snp", "tdx").
	measured, err := loadMeasuredIdentity(ctx, string(platform.Family()), api, cfg.MeasuredPoliciesFile)
	if err != nil {
		return nil, fmt.Errorf("verify this boot's identity: %w", err)
	}
	if measured.OperatorKeyErr != nil {
		return nil, fmt.Errorf("launch configuration requires a measured launch key: %w", measured.OperatorKeyErr)
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
	if err := doc.authorizeKey(pub); err != nil {
		return nil, err
	}
	return &Verified{document: *doc, operatorPub: pub}, nil
}
