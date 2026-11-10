//go:build linux

package objectcustody

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

// Derive is a startup operation inside an independently approved measured
// custodian, after native verification of its executable and Document().
// Recovery requires the same chip, boot measurement and fixed parameters.
// The device ioctl is synchronous; cancellation is checked before and after it.
func Derive(
	ctx context.Context,
	config *Config,
) (*Material, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if config == nil || len(config.document) == 0 {
		return nil, errors.New("object custody: parsed measured configuration required")
	}
	device := &client.LinuxDevice{}
	if err := device.Open("/dev/sev-guest"); err != nil {
		return nil, err
	}
	defer device.Close()
	return deriveFromDevice(
		ctx,
		config,
		device,
	)
}

func deriveFromDevice(
	ctx context.Context,
	config *Config,
	device client.Device,
) (*Material, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report, err := client.GetReportAtVmpl(
		device,
		[64]byte{},
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := config.checkReport(report); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	response, err := client.GetDerivedKeyAcknowledgingItsLimitations(
		device,
		&client.SnpDerivedKeyReq{
			UseVCEK:    true,
			Vmpl:       0,
			GuestSVN:   config.parameters.GuestSVN,
			TCBVersion: config.parameters.TCB,
			GuestFieldSelect: client.GuestFieldSelect{
				GuestPolicy: true,
				ImageID:     true,
				FamilyID:    true,
				Measurement: true,
				GuestSVN:    true,
				TCBVersion:  true,
			},
		},
	)
	if response != nil {
		defer clear(response.Data[:])
	}
	if err != nil {
		return nil, err
	}
	if response.Status != 0 || bytes.Equal(
		response.Data[:],
		make(
			[]byte,
			32,
		),
	) {
		return nil, errors.New("object custody: firmware refused key derivation")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return deriveMaterial(
		response.Data[:],
		config.document,
	)
}

func (c *Config) checkReport(report *sevsnp.Report) error {
	if report == nil || report.Version < abi.ReportVersion3 || report.Version > abi.MaxSupportedReportVersion {
		return errors.New("object custody: supported native SNP report required")
	}
	policy, err := abi.ParseSnpPolicy(report.Policy)
	digest := sha256.Sum256(c.document)
	if err != nil || policy.Debug || policy.MigrateMA || report.Vmpl != 0 || !bytes.Equal(
		report.HostData,
		digest[:],
	) {
		return errors.New("object custody: non-debug, non-migratable VMPL0 report must bind the original custody document")
	}
	selected := kds.DecomposeTCBVersion(kds.TCBVersion(c.parameters.TCB))
	committed := kds.DecomposeTCBVersion(kds.TCBVersion(report.CommittedTcb))
	current := kds.DecomposeTCBVersion(kds.TCBVersion(report.CurrentTcb))
	if report.GuestSvn < c.parameters.GuestSVN || !kds.TCBPartsLE(
		selected,
		committed,
	) || !kds.TCBPartsLE(
		committed,
		current,
	) {
		return errors.New("object custody: fixed derivation parameters exceed the committed firmware or guest SVN")
	}
	return nil
}

func deriveMaterial(
	root []byte,
	document []byte,
) (*Material, error) {
	if len(root) != 32 || len(document) == 0 {
		return nil, errors.New("object custody: hardware root and original document required")
	}
	digest := sha256.Sum256(document)
	seed, err := hkdf.Key(
		sha256.New,
		root,
		digest[:],
		"c8s/object-custody/v1/authority",
		ed25519.SeedSize,
	)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	key, err := hkdf.Key(
		sha256.New,
		root,
		digest[:],
		"c8s/object-custody/v1/state-key",
		32,
	)
	if err != nil {
		return nil, err
	}
	return &Material{
		Signer:   ed25519.NewKeyFromSeed(seed),
		StateKey: key,
	}, nil
}
