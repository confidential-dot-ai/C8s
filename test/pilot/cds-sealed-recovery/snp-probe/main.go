//go:build linux

// snp-probe tests a disposable secret across SNP guest restarts. It is not a
// custodian: no CDS key input, key-release API, software fallback or provider
// credentials are supported. Run only inside an explicitly owned pilot guest.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

// Public derivation inputs survive restarts and firmware SVN increases. The
// firmware enforces whether the requested GuestSVN/TCBVersion is derivable.
type envelope struct {
	Version        int    `json:"version"`
	Measurement    string `json:"measurement"`
	LaunchSHA256   string `json:"launch_sha256"`
	GuestSVN       uint32 `json:"guest_svn"`
	TCBVersion     uint64 `json:"tcb_version"`
	SentinelSHA256 string `json:"sentinel_sha256"`
	Ciphertext     []byte `json:"ciphertext"`
}

// Only an authenticated-decryption failure establishes the negative case.
// A firmware/device failure must never count as different-chip rejection.
var errCapsuleAuthentication = errors.New("hardware/configuration cannot open this capsule")

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !s.Mode().IsRegular() || s.Size() == 0 || s.Size() > max {
		return nil, errors.New("bounded regular input file required")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && (len(b) == 0 || int64(len(b)) > max) {
		err = errors.New("input size changed beyond bounds")
	}
	return b, err
}

func decodeEnvelope(body []byte) (envelope, error) {
	var e envelope
	if err := strictjson.Validate(body); err != nil {
		return e, err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	hash, err := hex.DecodeString(e.SentinelSHA256)
	if err != nil || len(hash) != sha256.Size || e.Version != 1 || len(e.Ciphertext) != 32+12+16 {
		return e, errors.New("invalid probe capsule")
	}
	return e, nil
}

func checkReport(r *sevsnp.Report, nonce [64]byte, measurement, launch []byte) error {
	if r == nil || !bytes.Equal(r.ReportData, nonce[:]) || r.Vmpl != 0 || !bytes.Equal(r.Measurement, measurement) {
		return errors.New("SNP report does not match the requested nonce, VMPL or approved measurement")
	}
	p, err := abi.ParseSnpPolicy(r.Policy)
	if err != nil || p.Debug || p.MigrateMA {
		return errors.New("non-debug, non-migratable SNP policy required")
	}
	hostData := runtimemeasure.HostData(launch)
	if !bytes.Equal(r.HostData, hostData[:]) {
		return errors.New("SNP HOST_DATA does not bind the exact launch file")
	}
	return nil
}

func keyRequest(e envelope) *client.SnpDerivedKeyReq {
	return &client.SnpDerivedKeyReq{UseVCEK: true, Vmpl: 0, GuestSVN: e.GuestSVN, TCBVersion: e.TCBVersion,
		GuestFieldSelect: client.GuestFieldSelect{GuestPolicy: true, ImageID: true, FamilyID: true, Measurement: true, GuestSVN: true, TCBVersion: true}}
}

func probeCipher(root []byte, e envelope) (cipher.AEAD, []byte, error) {
	e.Ciphertext = nil
	meta, _ := json.Marshal(e)
	aad := append([]byte("c8s/cds-snp-disposable-probe/v1\x00"), meta...)
	// HOST_DATA is NOT an SNP derived-key field. The measured program must
	// check it before this application-level configuration binding is useful.
	key, err := hkdf.Key(sha256.New, root, nil, string(aad), 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	return aead, aad, err
}

func probe(d client.Device, mode string, measurement, launch []byte, e envelope) (envelope, error) {
	var nonce [64]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return e, err
	}
	r, err := client.GetReportAtVmpl(d, nonce, 0)
	if err != nil {
		return e, err
	}
	if err := checkReport(r, nonce, measurement, launch); err != nil {
		return e, err
	}
	launchHash := sha256.Sum256(launch)
	if mode == "seal" {
		e = envelope{Version: 1, Measurement: hex.EncodeToString(measurement), LaunchSHA256: hex.EncodeToString(launchHash[:]), GuestSVN: r.GuestSvn, TCBVersion: r.CommittedTcb}
	} else if e.Measurement != hex.EncodeToString(measurement) || e.LaunchSHA256 != hex.EncodeToString(launchHash[:]) {
		return e, errors.New("capsule belongs to another image or launch configuration")
	}
	response, err := client.GetDerivedKeyAcknowledgingItsLimitations(d, keyRequest(e))
	if err != nil {
		return e, err
	}
	defer clear(response.Data[:])
	if response.Status != 0 {
		return e, errors.New("firmware rejected derived-key request")
	}
	var sentinel []byte
	if mode == "seal" {
		sentinel = make([]byte, 32)
		defer clear(sentinel)
		if _, err := rand.Read(sentinel); err != nil {
			return e, err
		}
		h := sha256.Sum256(sentinel)
		e.SentinelSHA256 = hex.EncodeToString(h[:])
	}
	aead, aad, err := probeCipher(response.Data[:], e)
	if err != nil {
		return e, err
	}
	if mode == "seal" {
		e.Ciphertext = aead.Seal(nil, nil, sentinel, aad)
	} else {
		sentinel, err = aead.Open(nil, nil, e.Ciphertext, aad)
		if err != nil {
			return e, errCapsuleAuthentication
		}
		defer clear(sentinel)
		h := sha256.Sum256(sentinel)
		if hex.EncodeToString(h[:]) != e.SentinelSHA256 {
			return e, errors.New("recovered sentinel changed")
		}
	}
	return e, nil
}

func writeNew(path string, e envelope) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("snp-probe", flag.ContinueOnError)
	mode := flags.String("mode", "", "seal or open; disposable sentinel only")
	path := flags.String("capsule-file", "", "encrypted probe capsule; seal refuses overwrite")
	launchPath := flags.String("launch-file", "", "exact independently approved launch file")
	pin := flags.String("measurement", "", "independently approved 48-byte SNP measurement in hex")
	if err := flags.Parse(args); err != nil {
		return err
	}
	measurement, err := hex.DecodeString(*pin)
	if err != nil || len(measurement) != 48 || bytes.Equal(measurement, make([]byte, 48)) || flags.NArg() != 0 || (*mode != "seal" && *mode != "open") || *path == "" || *launchPath == "" {
		return errors.New("mode, capsule-file, launch-file and nonzero SNP measurement are required")
	}
	launch, err := readBounded(*launchPath, 1<<20)
	if err != nil {
		return err
	}
	var e envelope
	if *mode == "open" {
		body, err := readBounded(*path, 4096)
		if err != nil {
			return err
		}
		e, err = decodeEnvelope(body)
		if err != nil {
			return err
		}
	}
	// Fixed real device: no mock/file key option or SDK command-line overrides.
	d := &client.LinuxDevice{}
	if err := d.Open("/dev/sev-guest"); err != nil {
		return err
	}
	defer d.Close()
	e, err = probe(d, *mode, measurement, launch, e)
	if err != nil {
		return err
	}
	if *mode == "seal" {
		if err := writeNew(*path, e); err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(struct {
		Operation                 string `json:"operation"`
		SentinelSHA256            string `json:"sentinel_sha256"`
		Measurement               string `json:"measurement"`
		LaunchSHA256              string `json:"launch_sha256"`
		AttestationChainVerified  bool   `json:"attestation_chain_verified"`
		OperatorExclusionVerified bool   `json:"operator_exclusion_verified"`
		VersionRetirementVerified bool   `json:"version_retirement_verified"`
		FullAcceptancePassed      bool   `json:"full_acceptance_passed"`
	}{Operation: *mode, SentinelSHA256: e.SentinelSHA256, Measurement: e.Measurement, LaunchSHA256: e.LaunchSHA256})
}

func main() {
	entry := run
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			entry, args = serve, args[1:]
		case "request":
			entry, args = request, args[1:]
		}
	}
	if err := entry(args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "snp-probe:", err)
		os.Exit(1)
	}
}
