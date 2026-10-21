package steps

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	sevabi "github.com/google/go-sev-guest/abi"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// withMeasurement is the {platform, evidence} envelope with edit applied to
// its launch measurement: an SEV-SNP report's MEASUREMENT or a TDX quote's
// MRTD, the rest of the report or quote as it was.
func withMeasurement(envelope []byte, edit func(measurement []byte)) ([]byte, error) {
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, err
	}
	var err error
	switch env.Platform.Family() {
	case teetypes.FamilySNP:
		var ev snp.SnpEvidence
		if err := json.Unmarshal(env.Evidence, &ev); err != nil {
			return nil, fmt.Errorf("the SEV-SNP evidence: %w", err)
		}
		if ev.AttestationReport, err = editBase64(ev.AttestationReport, func(raw []byte) ([]byte, error) {
			report, err := sevabi.ReportToProto(raw)
			if err != nil {
				return nil, err
			}
			edit(report.Measurement)
			out, err := sevabi.ReportToAbiBytes(report)
			return append(out, raw[len(out):]...), err
		}); err != nil {
			return nil, fmt.Errorf("the SEV-SNP report: %w", err)
		}
		env.Evidence, err = json.Marshal(ev)
	case teetypes.FamilyTDX:
		var ev tdx.TdxEvidence
		if err := json.Unmarshal(env.Evidence, &ev); err != nil {
			return nil, fmt.Errorf("the TDX evidence: %w", err)
		}
		if ev.Quote, err = editBase64(ev.Quote, func(raw []byte) ([]byte, error) {
			quote, err := tdxabi.QuoteToProto(raw)
			if err != nil {
				return nil, err
			}
			switch q := quote.(type) {
			case *tdxpb.QuoteV4:
				edit(q.GetTdQuoteBody().GetMrTd())
			case *tdxpb.QuoteV5:
				edit(q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5().GetMrTd())
			default:
				return nil, fmt.Errorf("a %T, whose MRTD this suite does not edit", quote)
			}
			return tdxabi.QuoteToAbiBytes(quote)
		}); err != nil {
			return nil, fmt.Errorf("the TDX quote: %w", err)
		}
		env.Evidence, err = json.Marshal(ev)
	default:
		return nil, skipf("the %s evidence carries a launch measurement this suite does not edit", env.Platform)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

func editBase64(s string, edit func([]byte) ([]byte, error)) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	out, err := edit(raw)
	return base64.StdEncoding.EncodeToString(out), err
}
