package snpaccept

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify/trust"
)

type recordingGetter struct {
	base trust.HTTPSGetter
	data Collateral
}

func (g *recordingGetter) Get(url string) ([]byte, error) {
	if b, ok := g.data[url]; ok {
		return b, nil
	}
	b, err := g.base.Get(url)
	if err == nil {
		g.data[url] = bytes.Clone(b)
	}
	return b, err
}
func (g *recordingGetter) GetContext(ctx context.Context, url string) ([]byte, error) {
	if b, ok := g.data[url]; ok {
		return b, nil
	}
	var b []byte
	var err error
	if c, ok := g.base.(interface {
		GetContext(context.Context, string) ([]byte, error)
	}); ok {
		b, err = c.GetContext(ctx, url)
	} else {
		b, err = g.base.Get(url)
	}
	if err == nil {
		g.data[url] = bytes.Clone(b)
	}
	return b, err
}

func Verify(ctx context.Context, q Request, reply Reply, launch []byte) (map[string]any, Collateral, error) {
	m, err := hex.DecodeString(q.Measurement)
	if err != nil || len(m) != 48 || len(q.Nonce) != 32 {
		return nil, nil, errors.New("independent pin and nonce required")
	}
	data := Binding(q, reply.Result)
	config := sha256.Sum256(launch)
	g := &recordingGetter{snp.DefaultKDSGetter(40*time.Second, 4*time.Second), make(Collateral)}
	_, err = snp.VerifyReportContext(ctx, reply.Report, nil, teetypes.VerifyParams{ExpectedReportData: data[:], ExpectedInitDataHash: config[:], ExpectedLaunchDigest: m}, teetypes.PlatformSNP, snp.MinReportVersion, snp.Options{CheckRevocations: true, Getter: g})
	if err != nil {
		return nil, nil, err
	}
	r, err := abi.ReportToProto(reply.Report)
	if err != nil {
		return nil, nil, err
	}
	p, err := abi.ParseSnpPolicy(r.Policy)
	if err != nil || p.MigrateMA || p.Debug || r.Vmpl != 0 {
		return nil, nil, errors.New("debug/migration/VMPL policy refused")
	}
	chip := sha256.Sum256(r.ChipId)
	guest := sha256.Sum256(r.ReportId)
	return map[string]any{"attestation_chain_verified": true, "issuer_crl_checked": true, "measurement": q.Measurement, "launch_sha256": hex.EncodeToString(config[:]), "chip_id_sha256": hex.EncodeToString(chip[:]), "guest_report_id_sha256": hex.EncodeToString(guest[:]), "result": reply.Result, "production_ready": false, "operator_exclusion_qualified": false}, g.data, nil
}
