package allowlist

import (
	"strings"
	"testing"
)

// Only a measured boot config marks a static pod's entry: the strict JSON
// ingest refuses the key and a served document's is ignored.
func TestStaticPodIsYAMLOnly(t *testing.T) {
	doc := `{"schema":"` + Schema + `","workloads":{"entry":{"staticPod":true,"containers":[{"digest":"` + digestA + `","command":{"policy":"exact","argv":["/x"]},"args":{"policy":"deny"}}]}}}`
	if _, err := ParseJSON([]byte(doc)); err == nil || !strings.Contains(err.Error(), "staticPod") {
		t.Fatalf("ParseJSON = %v, want the staticPod key refused", err)
	}
	served, err := ParseServedJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if served.Workloads["entry"].StaticPod {
		t.Fatal("a served document marked a static pod's entry")
	}
}
