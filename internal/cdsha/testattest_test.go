package cdsha

import (
	"encoding/json"
	"errors"
)

// testAttestor is the tests' stand-in for a TEE: its "evidence" is an
// unsigned JSON claim. It lives in a test file so the multi-replica tests
// run in every build; the c8s_dev MockAttestor is the same idea for dev
// clusters without TEEs.
type testAttestor struct{ measurement string }

type testEvidence struct {
	Measurement string   `json:"measurement"`
	ReportData  [48]byte `json:"report_data"`
}

func (a testAttestor) Evidence(rd [48]byte) ([]byte, error) {
	return json.Marshal(testEvidence{Measurement: a.measurement, ReportData: rd})
}

func (testAttestor) Verify(ev []byte) (Claims, error) {
	var e testEvidence
	if err := json.Unmarshal(ev, &e); err != nil {
		return Claims{}, err
	}
	if e.Measurement == "" {
		return Claims{}, errors.New("test evidence without measurement")
	}
	return Claims{Measurement: e.Measurement, ReportData: e.ReportData}, nil
}
