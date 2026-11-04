//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/client/linuxabi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"
)

// Software IO fixture only. It checks our request handling and records the
// inputs sent to firmware; it provides no evidence about actual SNP sealing.
type fixtureDevice struct {
	client.Device
	report    *sevsnp.Report
	root      byte
	keyCalls  int
	keyError  error
	keyStatus uint32
	request   *linuxabi.SnpDerivedKeyReqABI
}

func (d *fixtureDevice) Ioctl(command uintptr, argument any) (uintptr, error) {
	req := argument.(*linuxabi.SnpUserGuestRequest)
	switch command {
	case linuxabi.IocSnpGetReport:
		r := proto.Clone(d.report).(*sevsnp.Report)
		r.ReportData = req.ReqData.(*linuxabi.SnpReportReqABI).ReportData[:]
		raw, err := abi.ReportToAbiBytes(r)
		if err != nil {
			return 0, err
		}
		copy(req.RespData.(*linuxabi.SnpReportRespABI).Data[:], raw)
	case linuxabi.IocSnpGetDerivedKey:
		d.keyCalls++
		if d.keyError != nil {
			return 0, d.keyError
		}
		req.RespData.(*linuxabi.SnpDerivedKeyRespABI).Status = d.keyStatus
		d.request = req.ReqData.(*linuxabi.SnpDerivedKeyReqABI)
		params, _ := json.Marshal(d.request)
		key := sha256.Sum256(append([]byte{d.root}, params...))
		req.RespData.(*linuxabi.SnpDerivedKeyRespABI).Data = key
	default:
		return 0, fmt.Errorf("unexpected device command")
	}
	return 0, nil
}

func deviceFixture() (*fixtureDevice, []byte, []byte) {
	launch := []byte("disposable SNP probe launch")
	hd := runtimemeasure.HostData(launch)
	measurement := bytes.Repeat([]byte{0xab}, 48)
	return &fixtureDevice{root: 1, report: &sevsnp.Report{
		Version: 2, Policy: abi.SnpPolicyToBytes(abi.SnpPolicy{}),
		GuestSvn: 1, CommittedTcb: 1, Measurement: measurement, HostData: hd[:],
		FamilyId: make([]byte, 16), ImageId: make([]byte, 16), ReportId: make([]byte, 32),
		ReportIdMa: make([]byte, 32), IdKeyDigest: make([]byte, 48), AuthorKeyDigest: make([]byte, 48),
		ChipId: make([]byte, 64), Signature: make([]byte, 512),
	}}, measurement, launch
}

func TestProbeRetainsDerivationParametersAcrossRestart(t *testing.T) {
	d, measurement, launch := deviceFixture()
	e, err := probe(d, "seal", measurement, launch, envelope{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "capsule.json")
	if err := writeNew(path, e); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(path, envelope{}); err == nil {
		t.Fatal("overwrote existing capsule")
	}
	body, err := readBounded(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	e, err = decodeEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	// A new device object reports newer SVNs. Opening must request the old
	// derivation parameters retained in the authenticated capsule.
	next, _, _ := deviceFixture()
	next.report.GuestSvn, next.report.CommittedTcb = 2, 2
	opened, err := probe(next, "open", measurement, launch, e)
	if err != nil || opened.SentinelSHA256 != e.SentinelSHA256 {
		t.Fatalf("recover: %v", err)
	}
	if next.request.GuestSVN != 1 || next.request.TCBVersion != 1 || next.request.GuestFieldSelect != 63 || next.request.RootKeySelect != 0 || next.request.Vmpl != 0 {
		t.Fatal("changed protected root or derivation context")
	}
	next.root = 2
	if _, err := probe(next, "open", measurement, launch, e); err == nil {
		t.Fatal("another simulated chip opened the capsule")
	}
	for _, change := range []string{"ciphertext", "config", "measurement", "svn", "digest"} {
		t.Run(change, func(t *testing.T) {
			next.root = 1
			bad := e
			bad.Ciphertext = bytes.Clone(e.Ciphertext)
			switch change {
			case "ciphertext":
				bad.Ciphertext[0] ^= 1
			case "config":
				bad.LaunchSHA256 = "other"
			case "measurement":
				bad.Measurement = "other"
			case "svn":
				bad.GuestSVN++
			case "digest":
				bad.SentinelSHA256 = "other"
			}
			if _, err := probe(next, "open", measurement, launch, bad); err == nil {
				t.Fatal("opened changed capsule")
			}
		})
	}
}

func TestProbeChecksLaunchBeforeRequestingKey(t *testing.T) {
	for _, change := range []string{"debug", "migration", "vmpl", "measurement", "host data", "policy"} {
		t.Run(change, func(t *testing.T) {
			d, measurement, launch := deviceFixture()
			switch change {
			case "debug":
				d.report.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: true})
			case "migration":
				d.report.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{MigrateMA: true})
			case "vmpl":
				d.report.Vmpl = 1
			case "measurement":
				d.report.Measurement = bytes.Repeat([]byte{0xcd}, 48)
			case "host data":
				d.report.HostData[0] ^= 1
			case "policy":
				d.report.Policy = 0
			}
			if _, err := probe(d, "seal", measurement, launch, envelope{}); err == nil {
				t.Fatal("accepted disallowed guest")
			}
			if d.keyCalls != 0 {
				t.Fatal("requested key before checking launch")
			}
		})
	}
}

func TestProbeRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	for _, body := range []string{`{"version":1,"version":1}`, `{} {}`, `{"unknown":1}`, `null`} {
		if _, err := decodeEnvelope([]byte(body)); err == nil {
			t.Fatal("accepted invalid capsule")
		}
	}
	path := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(path, make([]byte, 4097), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(path, 4096); err == nil {
		t.Fatal("read unbounded capsule")
	}
	if err := run([]string{"-mode=seal", "-measurement=00"}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted missing approved bindings")
	}
}
