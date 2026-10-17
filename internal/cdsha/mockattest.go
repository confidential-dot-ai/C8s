//go:build c8s_dev

package cdsha

import (
	"encoding/json"
	"errors"
)

// MockAttestor is UNSAFE and exists only in c8s_dev builds. Its "evidence" is
// an unsigned JSON claim, so anyone can forge it. It lets the protocol run in
// a cluster without TEEs.
type MockAttestor struct{ Measurement string }

type mockEvidence struct {
	Measurement string   `json:"measurement"`
	ReportData  [48]byte `json:"report_data"`
}

// Evidence implements Attestor.
func (m MockAttestor) Evidence(rd [48]byte) ([]byte, error) {
	return json.Marshal(mockEvidence{Measurement: m.Measurement, ReportData: rd})
}

// Verify implements Attestor. There is no signature to check.
func (MockAttestor) Verify(ev []byte) (Claims, error) {
	var e mockEvidence
	if err := json.Unmarshal(ev, &e); err != nil {
		return Claims{}, err
	}
	if e.Measurement == "" {
		return Claims{}, errors.New("mock evidence without measurement")
	}
	return Claims{Measurement: e.Measurement, ReportData: e.ReportData}, nil
}

func init() {
	devAttestors["mock"] = func(o AttestorOptions) (Attestor, error) {
		return MockAttestor{Measurement: o.MockMeasurement}, nil
	}
}
