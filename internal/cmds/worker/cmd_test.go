package worker

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newFiles writes the CDS pin and CA files `worker new` reads.
func newFiles(t *testing.T, nodeSubnet string) (pinPath, caPath string) {
	t.Helper()
	dir := t.TempDir()
	pinPath = filepath.Join(dir, "cds-pin.json")
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(pinPath, []byte(testCDSPin(t, cdsConfig(t, nodeSubnet))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(selfSigned(t, caTemplate())), 0o600); err != nil {
		t.Fatal(err)
	}
	return pinPath, caPath
}

func runNew(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"new"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func kubernetesFlags(caPath string) []string {
	return []string{
		"--api-server", "acme.k8s.example:443",
		"--ca-certificate", caPath,
		"--pod-cidr", "10.52.0.0/16",
		"--service-cidr", "10.53.0.0/16",
		"--cluster-dns", "10.53.0.10",
	}
}

func TestNewWritesTheDocumentItsFlagsName(t *testing.T) {
	pinPath, caPath := newFiles(t, "192.168.0.0/16")
	out := filepath.Join(t.TempDir(), "worker.yaml")
	args := append([]string{
		"--out", out,
		"--cds-address", "cds.acme.example:8443",
		"--cds-pin", pinPath,
		"--cds-pin-floor", "3",
		"--router-hostname", "api.acme.example",
		"--acme-email", "ops@acme.example",
	}, kubernetesFlags(caPath)...)
	if _, err := runNew(t, args...); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := os.ReadFile(pinPath)
	ca, _ := os.ReadFile(caPath)
	if doc.CDS.Address != "cds.acme.example:8443" || doc.CDS.Measurements != string(pin) || doc.CDS.PinFloor != 3 {
		t.Fatalf("cds = %+v, want the flags' address, floor and the pin file's bytes", doc.CDS)
	}
	if doc.Router == nil || len(doc.Router.Hostnames) != 1 || doc.Router.Hostnames[0] != "api.acme.example" || doc.Router.ACMEEmail != "ops@acme.example" {
		t.Fatalf("router = %+v", doc.Router)
	}
	want := Kubernetes{
		APIServer:     "acme.k8s.example:443",
		CACertificate: string(ca),
		PodCIDR:       "10.52.0.0/16",
		ServiceCIDR:   "10.53.0.0/16",
		ClusterDNS:    "10.53.0.10",
	}
	if doc.Kubernetes != want {
		t.Fatalf("kubernetes = %+v, want %+v", doc.Kubernetes, want)
	}
}

func TestNewWritesToStdoutWithoutARouterBlockWhenNoneIsNamed(t *testing.T) {
	pinPath, caPath := newFiles(t, "192.168.0.0/16")
	args := append([]string{"--cds-address", "cds.acme.example:8443", "--cds-pin", pinPath}, kubernetesFlags(caPath)...)
	stdout, err := runNew(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "router:") {
		t.Fatalf("drafted a router block no flag named:\n%s", stdout)
	}
	doc, err := Parse([]byte(stdout))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Router != nil {
		t.Fatalf("router = %+v, want none", doc.Router)
	}
}

func TestNewRefusesADocumentAWorkerWouldRefuse(t *testing.T) {
	pinPath, caPath := newFiles(t, "10.52.0.0/24")
	out := filepath.Join(t.TempDir(), "worker.yaml")
	args := append([]string{"--out", out, "--cds-address", "cds.acme.example:8443", "--cds-pin", pinPath}, kubernetesFlags(caPath)...)
	_, err := runNew(t, args...)
	if err == nil || !strings.Contains(err.Error(), "overlaps the cluster range 10.52.0.0/16") {
		t.Fatalf("got %v, want the node subnet overlap refused", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused document was written: %v", err)
	}
}
