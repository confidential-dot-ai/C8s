package verify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// In auto mode the target may be a Trust Authority reached directly, so a pin
// embedding an initdata document with no agent policy is refused whatever
// --kind says. Pins that embed no launch file are another guest's and pass.
func TestAPinEmbeddingAnInitdataDocumentNeedsItsPolicyInEveryKind(t *testing.T) {
	hex96 := func(b string) string { return strings.Repeat(b, 48) }
	pin := func(launchFile string) refvalues.ReferenceValues {
		t.Helper()
		entry := ""
		if launchFile != "" {
			encoded, err := json.Marshal(launchFile)
			if err != nil {
				t.Fatal(err)
			}
			entry = `,"launch_file":` + string(encoded)
		}
		values, err := refvalues.Parse([]byte(`{"schema_version":"2","tee":"tdx","measurements":[{"name":"ta","mrtd":"` + hex96("aa") +
			`","rtmr":[null,"` + hex96("bb") + `","` + hex96("cc") + `"]` + entry + `}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	const document = "algorithm = \"sha384\"\n[data]\n\"ta-config.yaml\" = \"schemaVersion: c8s-ta/v1\"\n"
	withPolicy := document + "\"policy.rego\" = \"package agent_policy\"\n"
	for _, kind := range []string{"auto", "router", "ta"} {
		if err := requireTAIdentity(config{kind: kind}, pin(document)); err == nil || !strings.Contains(err.Error(), "policy.rego") {
			t.Errorf("kind %s: a document with no policy = %v, want a refusal naming policy.rego", kind, err)
		}
		if err := requireTAIdentity(config{kind: kind}, pin(withPolicy)); err != nil {
			t.Errorf("kind %s: a document with a policy was refused: %v", kind, err)
		}
	}
	if err := requireTAIdentity(config{kind: "auto"}, pin("")); err != nil {
		t.Errorf("a pin embedding no launch file was refused: %v", err)
	}
}
