package cdsha

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// attestor is the attestation-api on this CVM's own loopback: the one service
// that makes this replica's evidence and the one that judges a peer's.
type attestor struct {
	serviceURL string
	timeout    time.Duration
	client     remote.Client
}

func newAttestor(serviceURL string, timeout time.Duration) (attestor, error) {
	if err := requireOnThisVM(serviceURL); err != nil {
		return attestor{}, err
	}
	return attestor{
		serviceURL: serviceURL,
		timeout:    timeout,
		client:     remote.NewClientWithHTTP(serviceURL, armtls.NewDirectHTTPClient(timeout)),
	}, nil
}

// requireOnThisVM refuses an attestation-api outside this CVM, whose verdicts
// the host would choose: a unix socket of this guest, or its loopback.
func requireOnThisVM(serviceURL string) error {
	if strings.HasPrefix(serviceURL, "unix://") {
		return nil
	}
	parsed, err := url.Parse(serviceURL)
	if err != nil {
		return fmt.Errorf("attestation-api %q: %w", serviceURL, err)
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.IsLoopback() {
		return fmt.Errorf("attestation-api %q is not a unix socket or loopback address of this VM", serviceURL)
	}
	return nil
}

func (a attestor) attest(reportData [48]byte) (*agarmtls.Attestation, error) {
	response, err := a.client.Attest(
		context.Background(),
		remote.AttestRequest{ReportData: reportData[:]},
	)
	if err != nil {
		return nil, fmt.Errorf("attestation-api /attest: %w", err)
	}
	return agarmtls.NewAttestation(response.Envelope())
}

// ownVerdict is the attestation-api's verdict on this replica's own evidence,
// under no image pin: the launch identity the verdict reports is the pin.
func (a attestor) ownVerdict(evidence *agarmtls.Attestation, reportData [48]byte) (verdict, error) {
	envelope, err := evidence.Envelope()
	if err != nil {
		return verdict{}, err
	}
	request := remote.NewVerifyRequestNoToken(
		envelope,
		&remote.VerifyParams{ExpectedReportData: reportData[:]},
	)
	response, err := a.client.VerifyEnforced(context.Background(), request)
	if err != nil {
		return verdict{}, fmt.Errorf("attestation-api /verify: %w", err)
	}
	return newVerdict(response)
}

// verdict is evidence the attestation-api accepted, which a later admission
// set judges again.
type verdict struct {
	response         remote.VerifyResponse
	verifiedPlatform teetypes.PlatformType
}

// newVerdict takes the platform from what the service verified, so the
// envelope a peer presents never chooses the checks its evidence faces.
func newVerdict(response remote.VerifyResponse) (verdict, error) {
	if response.Result.Platform == "" {
		return verdict{}, errors.New("attestation-api verified no platform")
	}
	return verdict{response: response, verifiedPlatform: response.Result.Platform}, nil
}

// noRuntimeExtensions: a CDS guest extends RTMR[3] with its launch file alone.
var noRuntimeExtensions []string

// admittedBy judges the verdict against the images a replica admits, of which
// an empty set admits nobody.
func (v verdict) admittedBy(images []remote.ImagePin) error {
	if len(images) == 0 {
		return fmt.Errorf("%w: this replica admits no image", remote.ErrMeasurementNotAllowed)
	}
	return armtls.EnforceImages(v.response, images, v.verifiedPlatform, noRuntimeExtensions)
}

func (v verdict) runs(images []remote.ImagePin) bool {
	return v.admittedBy(images) == nil
}

const selfPinName = "this replica's image"

// imagePin is the launch identity this verdict reports, bound to launchFile.
func (v verdict) imagePin(launchFile []byte) (remote.ImagePin, error) {
	indices, identified := armtls.ImageRegisters(v.verifiedPlatform.Family())
	if !identified {
		return remote.ImagePin{}, fmt.Errorf("platform %q has no CDS image identity", v.verifiedPlatform)
	}
	digest, err := v.response.Result.Claims.LaunchMeasurement()
	if err != nil {
		return remote.ImagePin{}, err
	}
	registers, err := verifiedRegisters(v.response.Result.Claims, indices)
	if err != nil {
		return remote.ImagePin{}, err
	}
	return remote.ImagePin{
		Name:       selfPinName,
		Digest:     digest,
		Registers:  registers,
		LaunchFile: launchFile,
	}, nil
}

func verifiedRegisters(claims teetypes.Claims, indices []int) (map[int][]byte, error) {
	registers := make(map[int][]byte, len(indices))
	for _, index := range indices {
		value, err := claims.RTMR(index)
		if err != nil {
			return nil, err
		}
		registers[index] = value
	}
	return registers, nil
}
