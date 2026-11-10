//go:build linux

package objectcustody

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/go-sev-guest/abi"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

type firmwareDevice struct {
	report   *sevsnp.Report
	request  *labi.SnpDerivedKeyReqABI
	response *labi.SnpDerivedKeyRespABI
	status   uint32
	calls    int
	onDerive func()
}

func (*firmwareDevice) Open(string) error           { return nil }
func (*firmwareDevice) Close() error                { return nil }
func (*firmwareDevice) Product() *sevsnp.SevProduct { return nil }

func (d *firmwareDevice) Ioctl(
	command uintptr,
	input any,
) (uintptr, error) {
	request := input.(*labi.SnpUserGuestRequest)
	switch command {
	case labi.IocSnpGetReport:
		report, err := abi.ReportToAbiBytes(d.report)
		if err != nil {
			return 0, err
		}
		copy(
			request.RespData.(*labi.SnpReportRespABI).Data[:],
			report,
		)
	case labi.IocSnpGetDerivedKey:
		d.calls++
		d.request = request.ReqData.(*labi.SnpDerivedKeyReqABI)
		d.response = request.RespData.(*labi.SnpDerivedKeyRespABI)
		d.response.Status = d.status
		copy(
			d.response.Data[:],
			bytes.Repeat(
				[]byte{0x53},
				32,
			),
		)
		if d.onDerive != nil {
			d.onDerive()
		}
	default:
		return 0, errors.New("unexpected firmware operation")
	}
	return 0, nil
}

func testReport(config *Config) *sevsnp.Report {
	digest := sha256.Sum256(config.Document())
	return &sevsnp.Report{
		Version: abi.ReportVersion3,
		Policy:  abi.SnpPolicyToBytes(abi.SnpPolicy{}),
		FamilyId: make(
			[]byte,
			abi.FamilyIDSize,
		),
		ImageId: make(
			[]byte,
			abi.ImageIDSize,
		),
		SignatureAlgo: abi.SignEcdsaP384Sha384,
		ReportData: make(
			[]byte,
			abi.ReportDataSize,
		),
		Measurement: bytes.Repeat(
			[]byte{0x27},
			abi.MeasurementSize,
		),
		HostData: digest[:],
		IdKeyDigest: make(
			[]byte,
			abi.IDKeyDigestSize,
		),
		AuthorKeyDigest: make(
			[]byte,
			abi.AuthorKeyDigestSize,
		),
		ReportId: make(
			[]byte,
			abi.ReportIDSize,
		),
		ReportIdMa: make(
			[]byte,
			abi.ReportIDMASize,
		),
		ChipId: make(
			[]byte,
			abi.ChipIDSize,
		),
		Signature: make(
			[]byte,
			abi.SignatureSize,
		),
		CurrentTcb:   testTCB,
		CommittedTcb: testTCB,
	}
}

func TestHardwareDerivesOnceWithFixedParametersAndClearsRoot(t *testing.T) {
	config := testConfig(t)
	device := &firmwareDevice{report: testReport(config)}
	first, err := deriveFromDevice(
		context.Background(),
		config,
		device,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Clear()
	if device.calls != 1 || device.request.RootKeySelect != 0 || device.request.GuestFieldSelect != 63 ||
		device.request.GuestSVN != 0 || device.request.TCBVersion != testTCB || device.request.Vmpl != 0 {
		t.Fatal("derivation did not bind every selected field to its fixed measured parameters")
	}
	if !bytes.Equal(
		device.response.Data[:],
		make(
			[]byte,
			32,
		),
	) {
		t.Fatal("firmware root remained in the response")
	}
	device.report.CommittedTcb = 0x0302000000000202
	device.report.CurrentTcb = device.report.CommittedTcb
	device.report.GuestSvn = 3
	second, err := deriveFromDevice(
		context.Background(),
		config,
		device,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Clear()
	if device.request.TCBVersion != testTCB || device.request.GuestSVN != 0 ||
		!bytes.Equal(
			first.StateKey,
			second.StateKey,
		) || !bytes.Equal(
		first.Signer,
		second.Signer,
	) {
		t.Fatal("firmware advancement changed the selected derivation parameters or keys")
	}
	if bytes.Equal(
		first.Signer.Seed(),
		first.StateKey,
	) {
		t.Fatal("authority and state encryption reused the same derivation domain")
	}
	changed, err := deriveMaterial(
		bytes.Repeat(
			[]byte{0x53},
			32,
		),
		append(
			config.Document(),
			'\n',
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Clear()
	if bytes.Equal(
		first.StateKey,
		changed.StateKey,
	) || bytes.Equal(
		first.Signer,
		changed.Signer,
	) {
		t.Fatal("changing custody launch bytes retained authority or state key")
	}
	signer, stateKey := first.Signer, first.StateKey
	first.Clear()
	if first.Signer != nil || first.StateKey != nil || !bytes.Equal(
		signer,
		make(
			[]byte,
			len(signer),
		),
	) || !bytes.Equal(
		stateKey,
		make(
			[]byte,
			32,
		),
	) {
		t.Fatal("material cleanup retained secret slices")
	}
}

func TestHardwareRejectsUnsafeReportBeforeDerivation(t *testing.T) {
	config := testConfig(t)
	for _, test := range []struct {
		name   string
		mutate func(*sevsnp.Report)
	}{
		{
			"wrong launch",
			func(r *sevsnp.Report) { r.HostData[0] ^= 1 },
		},
		{
			"debug",
			func(r *sevsnp.Report) { r.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: true}) },
		},
		{
			"migration",
			func(r *sevsnp.Report) { r.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{MigrateMA: true}) },
		},
		{
			"VMPL",
			func(r *sevsnp.Report) { r.Vmpl = 1 },
		},
		{
			"old report",
			func(r *sevsnp.Report) { r.Version = abi.ReportVersion2 },
		},
		{
			"committed below selected",
			func(r *sevsnp.Report) { r.CommittedTcb-- },
		},
		{
			"componentwise floor",
			func(r *sevsnp.Report) { r.CommittedTcb = 0x0301000000000100; r.CurrentTcb = r.CommittedTcb },
		},
		{
			"provisional firmware",
			func(r *sevsnp.Report) { r.CurrentTcb-- },
		},
	} {
		t.Run(
			test.name,
			func(t *testing.T) {
				device := &firmwareDevice{report: testReport(config)}
				test.mutate(device.report)
				if material, err := deriveFromDevice(
					context.Background(),
					config,
					device,
				); err == nil || material != nil || device.calls != 0 {
					t.Fatal("unsafe report reached firmware derivation")
				}
			},
		)
	}
	config.parameters.GuestSVN = 1
	if err := config.checkReport(testReport(config)); err == nil {
		t.Fatal("accepted guest SVN below the fixed derivation parameter")
	}
}

func TestHardwareFailureAndCancellationReturnNoMaterial(t *testing.T) {
	config := testConfig(t)
	device := &firmwareDevice{
		report: testReport(config),
		status: 0x16,
	}
	if material, err := deriveFromDevice(
		context.Background(),
		config,
		device,
	); err == nil || material != nil {
		t.Fatal("accepted firmware refusal")
	}
	if !bytes.Equal(
		device.response.Data[:],
		make(
			[]byte,
			32,
		),
	) {
		t.Fatal("firmware refusal retained response bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	device = &firmwareDevice{
		report:   testReport(config),
		onDerive: cancel,
	}
	if material, err := deriveFromDevice(
		ctx,
		config,
		device,
	); !errors.Is(
		err,
		context.Canceled,
	) || material != nil {
		t.Fatal("canceled derivation returned material")
	}
	if !bytes.Equal(
		device.response.Data[:],
		make(
			[]byte,
			32,
		),
	) {
		t.Fatal("cancellation retained response bytes")
	}
	device = &firmwareDevice{report: testReport(config)}
	if material, err := deriveFromDevice(
		ctx,
		config,
		device,
	); !errors.Is(
		err,
		context.Canceled,
	) || material != nil || device.calls != 0 {
		t.Fatal("already canceled request reached derivation")
	}
	if material, err := Derive(
		context.Background(),
		nil,
	); err == nil || material != nil {
		t.Fatal("derivation accepted missing measured configuration")
	}
}
