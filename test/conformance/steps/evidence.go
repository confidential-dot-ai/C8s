package steps

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Where the launch measurement sits in the signed report body: an SNP
// report's MEASUREMENT, and a TDX quote's MRTD after the quote header (and,
// in a v5 quote, the body descriptor).
const (
	snpMeasurementOffset   = 0x90
	tdxHeaderLen           = 48
	tdxV5BodyDescriptorLen = 6
	tdxMRTDOffset          = 136
)

// unsignedEvidence is the {platform, evidence} envelope with one byte of its
// launch measurement changed, so its signature no longer verifies; false for
// a shape it does not edit.
func unsignedEvidence(envelope []byte) ([]byte, bool, error) {
	var env map[string]json.RawMessage
	var ev map[string]any
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(env["evidence"], &ev); err != nil {
		return nil, false, fmt.Errorf("the envelope's evidence: %w", err)
	}
	key, offset := "attestation_report", snpMeasurementOffset
	if _, ok := ev[key]; !ok {
		key = "quote"
	}
	s, ok := ev[key].(string)
	if !ok {
		return nil, false, nil
	}
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false, fmt.Errorf("the evidence's %s: %w", key, err)
	}
	if key == "quote" {
		if len(blob) < 2 {
			return nil, false, nil
		}
		switch binary.LittleEndian.Uint16(blob) {
		case 4:
			offset = tdxHeaderLen + tdxMRTDOffset
		case 5:
			offset = tdxHeaderLen + tdxV5BodyDescriptorLen + tdxMRTDOffset
		default:
			return nil, false, nil
		}
	}
	if offset >= len(blob) {
		return nil, false, nil
	}
	blob[offset] ^= 0xFF
	ev[key] = base64.StdEncoding.EncodeToString(blob)
	if env["evidence"], err = json.Marshal(ev); err != nil {
		return nil, false, err
	}
	out, err := json.Marshal(env)
	return out, true, err
}
