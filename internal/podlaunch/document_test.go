package podlaunch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every refusal of the document's own fields, one row per check.
func TestValidateDocumentFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"schema version", func(d *Document) { d.SchemaVersion = "c8s-launch/v1" }, "schemaVersion must be " + SchemaVersion},
		{"cluster ID", func(d *Document) { d.ClusterID = "Cluster_One" }, "clusterID must be an RFC1123 label"},
		{"node name", func(d *Document) { d.Node.Name = "node.one" }, "node.name must be an RFC1123 label"},
		{"platform", func(d *Document) { d.Image.Platform = "sgx" }, "image.platform must be tdx or snp"},
		{"uppercase measurement", func(d *Document) { d.Image.Measurement = strings.Repeat("AB", 48) }, "image.measurement"},
		{"short measurement", func(d *Document) { d.Image.Measurement = "11" }, "image.measurement"},
		{"one TDX register", func(d *Document) { delete(d.Image.RTMRs, 2) }, "a tdx image pins exactly RTMR[1] and RTMR[2]"},
		{"RTMR[3] for RTMR[2]", func(d *Document) { d.Image.RTMRs[3] = d.Image.RTMRs[2]; delete(d.Image.RTMRs, 2) }, "image.rtmrs[2] must be 96 lowercase hex characters"},
		{"SNP registers", func(d *Document) { d.Image.Platform = "snp" }, "a sev-snp image pins no RTMRs"},
		{"oversized key", func(d *Document) { d.PodOperatorPublicKey = strings.Repeat("k", maxLaunchKeySize+1) }, "launch public key is too large"},
		{"CDS chain pin", func(d *Document) { d.CDS.Chain = "not-a-pin" }, "cds.chain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, _, _ := testPodDocument(t, "tdx")
			tc.change(&doc)
			data, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHasRuntimeRegister(t *testing.T) {
	for platform, want := range map[string]bool{"tdx": true, "snp": false, "sgx": false} {
		if got := (Image{Platform: platform}).HasRuntimeRegister(); got != want {
			t.Errorf("%s HasRuntimeRegister = %v, want %v", platform, got, want)
		}
	}
}

func TestReadBoundedRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") }, "read "},
		{"directory", func(t *testing.T) string { return t.TempDir() }, "must be a regular file containing 1..8 bytes"},
		{"empty", func(t *testing.T) string { return writeFile(t, "empty", "") }, "must be a regular file containing 1..8 bytes"},
		{"over the limit", func(t *testing.T) string { return writeFile(t, "big", "123456789") }, "must be a regular file containing 1..8 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readBounded(tc.path(t), 8); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if data, err := readBounded(writeFile(t, "exact", "12345678"), 8); err != nil || string(data) != "12345678" {
		t.Fatalf("readBounded = %q, %v, want the whole file", data, err)
	}
}

// The staged file is decoded strictly and validated again.
func TestLoadStagedRefuses(t *testing.T) {
	doc, _, _ := testPodDocument(t, "tdx")
	data, err := json.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	invalid := doc
	invalid.Node.Name = "Node_One"
	invalidData, err := json.Marshal(&invalid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, content, want string
	}{
		{"not JSON", "launch: yaml\n", "decode staged launch configuration"},
		{"unknown field", strings.Replace(string(data), "{", `{"extra": 1,`, 1), "decode staged launch configuration"},
		{"trailing data", string(data) + "{}", "trailing data"},
		{"invalid document", string(invalidData), "node.name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadStaged(writeFile(t, "config.json", tc.content)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := LoadStaged(filepath.Join(t.TempDir(), "config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want a missing staged file", err)
	}
}
