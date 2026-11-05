//go:build linux

// Package snpaccept is the disposable, hardware-backed CDS acceptance fixture.
// It is not a production custodian or a software substitute for SNP.
package snpaccept

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"gopkg.in/yaml.v3"
)

type Parameters struct {
	GuestSVN uint32 `json:"guest_svn"`
	TCB      uint64 `json:"tcb_version"`
}

// DerivationIdentity exposes only public keys and a public configuration hash.
// It distinguishes firmware-key changes from application-context changes
// without disclosing a root, wrapping, signing, WAL or CA private key.
type DerivationIdentity struct {
	ContextSHA256     string `json:"context_sha256"`
	HardwarePublic    string `json:"hardware_public"`
	AuthorityPublic   string `json:"authority_public"`
	ExpectedAuthority string `json:"expected_authority"`
}

func (h *Hardware) PublicIdentity(ctx context.Context, p Parameters) (*DerivationIdentity, error) {
	b, _, err := authorityContext(h.Launch)
	if err != nil {
		return nil, err
	}
	root, err := h.root(ctx, p)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	contextHash := sha256.Sum256(b)
	public := func(salt []byte, domain string) (string, error) {
		seed, err := hkdf.Key(sha256.New, root, salt, domain, 32)
		if err != nil {
			return "", err
		}
		defer clear(seed)
		key := ed25519.NewKeyFromSeed(seed)
		defer clear(key)
		return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
	}
	hardware, err := public(nil, "c8s/cds-snp-acceptance/public-hardware-identity/v1")
	if err != nil {
		return nil, err
	}
	authority, err := public(contextHash[:], "c8s/cds-snp-acceptance/authority/v1")
	if err != nil {
		return nil, err
	}
	config, err := cdsconfig.Parse(h.Launch)
	if err != nil {
		return nil, err
	}
	return &DerivationIdentity{hex.EncodeToString(contextHash[:]), hardware, authority, config.HA.ObjectWALPilot.RecoveryAuthority}, nil
}

type deviceJob struct {
	ctx       context.Context
	operation func(client.Device) ([]byte, error)
	reply     chan deviceResult
}
type deviceResult struct {
	value []byte
	err   error
}

// Hardware owns the one firmware device behind a bounded mailbox. There is no
// file-key option, runtime code upload, shell, or remotely callable derivation.
type Hardware struct {
	jobs       chan deviceJob
	done       chan struct{}
	cancel     context.CancelFunc
	Launch     []byte
	ReportInfo *sevsnp.Report
}

func OpenHardware(ctx context.Context, launch []byte) (*Hardware, error) {
	d := &client.LinuxDevice{}
	if err := d.Open("/dev/sev-guest"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	h := &Hardware{jobs: make(chan deviceJob, 8), done: make(chan struct{}), cancel: cancel, Launch: bytes.Clone(launch)}
	go func() {
		defer close(h.done)
		defer d.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-h.jobs:
				if job.ctx.Err() != nil {
					continue
				}
				b, err := job.operation(d)
				select {
				case job.reply <- deviceResult{b, err}:
				case <-job.ctx.Done():
					clear(b)
				}
			}
		}
	}()
	raw, err := h.Report(ctx, [64]byte{})
	if err == nil {
		h.ReportInfo, err = abi.ReportToProto(raw)
	}
	if err == nil {
		err = h.check(h.ReportInfo)
	}
	if err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func (h *Hardware) check(r *sevsnp.Report) error {
	p, err := abi.ParseSnpPolicy(r.Policy)
	want := sha256.Sum256(h.Launch)
	if err != nil || p.Debug || p.MigrateMA || r.Vmpl != 0 || !bytes.Equal(r.HostData, want[:]) {
		return errors.New("non-debug, non-migratable VMPL0 SNP report must bind the exact launch file")
	}
	return nil
}

func (h *Hardware) call(ctx context.Context, op func(client.Device) ([]byte, error)) ([]byte, error) {
	job := deviceJob{ctx, op, make(chan deviceResult)}
	select {
	case h.jobs <- job:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.done:
		return nil, errors.New("hardware stopped")
	default:
		return nil, errors.New("firmware mailbox full")
	}
	select {
	case r := <-job.reply:
		return r.value, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.done:
		return nil, errors.New("hardware stopped")
	}
}
func (h *Hardware) Report(ctx context.Context, data [64]byte) ([]byte, error) {
	return h.call(ctx, func(d client.Device) ([]byte, error) { return client.GetRawReportAtVmpl(d, data, 0) })
}
func (h *Hardware) Close() { h.cancel(); <-h.done }

func (h *Hardware) root(ctx context.Context, p Parameters) ([]byte, error) {
	return h.call(ctx, func(d client.Device) ([]byte, error) {
		r, err := client.GetReportAtVmpl(d, [64]byte{}, 0)
		if err != nil {
			return nil, err
		}
		if err := h.check(r); err != nil {
			return nil, err
		}
		response, err := client.GetDerivedKeyAcknowledgingItsLimitations(d, &client.SnpDerivedKeyReq{UseVCEK: true, Vmpl: 0, GuestSVN: p.GuestSVN, TCBVersion: p.TCB,
			GuestFieldSelect: client.GuestFieldSelect{GuestPolicy: true, ImageID: true, FamilyID: true, Measurement: true, GuestSVN: true, TCBVersion: true}})
		if err != nil {
			return nil, err
		}
		defer clear(response.Data[:])
		if response.Status != 0 {
			return nil, errors.New("firmware rejected derivation")
		}
		return bytes.Clone(response.Data[:]), nil
	})
}

// This is only the application derivation context. SNP also unconditionally
// mixes HOST_DATA into its hardware key. The custodian therefore always boots
// the original template; a separate CDS guest boots the completed document.
func authorityContext(launch []byte) ([]byte, map[string]any, error) {
	parsed, err := cdsconfig.Parse(launch)
	if err != nil || parsed.HA == nil || parsed.HA.ObjectWALPilot == nil || parsed.HA.ObjectWALPilot.RecoveryAuthority == "" {
		return nil, nil, errors.New("protected object-WAL CDS launch required")
	}
	var doc map[string]any
	if err := yaml.Unmarshal(launch, &doc); err != nil {
		return nil, nil, err
	}
	ha, ok := doc["ha"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("ha missing")
	}
	w, ok := ha["objectWALPilot"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("object WAL missing")
	}
	delete(w, "recoveryAuthority")
	b, err := json.Marshal(doc)
	return b, doc, err
}

func (h *Hardware) material(ctx context.Context, p Parameters) (ed25519.PrivateKey, []byte, error) {
	b, _, err := authorityContext(h.Launch)
	if err != nil {
		return nil, nil, err
	}
	root, err := h.root(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	defer clear(root)
	contextHash := sha256.Sum256(b)
	seed, err := hkdf.Key(sha256.New, root, contextHash[:], "c8s/cds-snp-acceptance/authority/v1", 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(seed)
	signer := ed25519.NewKeyFromSeed(seed)
	full := sha256.Sum256(h.Launch)
	wrap, err := hkdf.Key(sha256.New, root, full[:], "c8s/cds-snp-acceptance/capsule/v1", 32)
	if err != nil {
		clear(signer)
		return nil, nil, err
	}
	return signer, wrap, nil
}

func (h *Hardware) Enroll(ctx context.Context) ([]byte, Parameters, error) {
	p := Parameters{h.ReportInfo.GuestSvn, h.ReportInfo.CommittedTcb}
	signer, wrap, err := h.material(ctx, p)
	if err != nil {
		return nil, p, err
	}
	defer clear(signer)
	defer clear(wrap)
	b, err := h.cdsLaunch(signer.Public().(ed25519.PublicKey))
	return b, p, err
}

func (h *Hardware) cdsLaunch(public ed25519.PublicKey) ([]byte, error) {
	_, doc, err := authorityContext(h.Launch)
	if err != nil {
		return nil, err
	}
	doc["ha"].(map[string]any)["objectWALPilot"].(map[string]any)["recoveryAuthority"] = base64.StdEncoding.EncodeToString(public)
	return yaml.Marshal(doc)
}

func (h *Hardware) Measurement() string { return hex.EncodeToString(h.ReportInfo.Measurement) }
func (h *Hardware) CheckMeasurement(want string) error {
	if want != h.Measurement() {
		return fmt.Errorf("unexpected image measurement")
	}
	return nil
}
