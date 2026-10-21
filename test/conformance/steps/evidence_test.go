package steps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestUnsignedEvidenceEditsTheLaunchMeasurement(t *testing.T) {
	quote := func(version byte) []byte { q := make([]byte, 700); q[0] = version; return q }
	for _, tc := range []struct {
		name, key string
		blob      []byte
		offset    int
	}{
		{"snp", "attestation_report", make([]byte, 1184), 0x90},
		{"tdx v4", "quote", quote(4), 184},
		{"tdx v5", "quote", quote(5), 190},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := fmt.Sprintf(`{"platform":"x","evidence":{%q:%q,"other":1}}`, tc.key, base64.StdEncoding.EncodeToString(tc.blob))
			out, ok, err := unsignedEvidence([]byte(env))
			if err != nil || !ok {
				t.Fatalf("unsignedEvidence: ok=%v err=%v", ok, err)
			}
			var got struct {
				Platform string         `json:"platform"`
				Evidence map[string]any `json:"evidence"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			blob, _ := base64.StdEncoding.DecodeString(got.Evidence[tc.key].(string))
			want := bytes.Clone(tc.blob)
			want[tc.offset] ^= 0xFF
			if !bytes.Equal(blob, want) {
				t.Errorf("the edited %s differs from the original at other than byte %d", tc.key, tc.offset)
			}
			if got.Platform != "x" || got.Evidence["other"] != float64(1) {
				t.Errorf("the rest of the envelope changed: %s", out)
			}
		})
	}
}

func TestUnsignedEvidenceLeavesOtherShapes(t *testing.T) {
	for _, env := range []string{
		`{"evidence":{"quote":"` + base64.StdEncoding.EncodeToString([]byte{3, 0, 0}) + `"}}`,
		`{"evidence":{"token":"abc"}}`,
	} {
		if _, ok, err := unsignedEvidence([]byte(env)); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want neither", env, ok, err)
		}
	}
}
