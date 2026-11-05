package worker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func publicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// cdsConfig is a CDS configuration the CDS's own parser accepts.
func cdsConfig(t *testing.T, nodeSubnets ...string) string {
	t.Helper()
	operator := publicKeyPEM(t)
	keys, err := operatorauth.ParseKeyBundle([]byte(operator))
	if err != nil {
		t.Fatal(err)
	}
	workloads, err := cdsconfig.MergeWorkloads([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "node", Digest: bytes.Repeat([]byte{0x11}, refvalues.DigestSize), Anchor: []byte(operator)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := cdsconfig.Format(cdsconfig.Document{
		ClusterID:    "acme",
		OperatorKeys: keys,
		Workloads:    workloads,
		Nodes:        nodes,
		NodeCIDRs:    nodeSubnets,
		LeafDNSNames: []string{"c8s.acme.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(config)
}

// testCDSPin pins the CDS image once per launch file, each entry bound to it.
func testCDSPin(t *testing.T, launchFiles ...string) string {
	t.Helper()
	pins := refvalues.ReferenceValues{Family: teetypes.FamilySNP}
	for i, launchFile := range launchFiles {
		pins.Images = append(pins.Images, remote.ImagePin{
			Name:       fmt.Sprintf("cds-%d", i),
			Digest:     bytes.Repeat([]byte{0x50}, refvalues.DigestSize),
			LaunchFile: []byte(launchFile),
		})
	}
	data, err := refvalues.Format(pins)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func testDigestOnlyPin(t *testing.T) string {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{Name: "cds", Digest: bytes.Repeat([]byte{0x50}, refvalues.DigestSize)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func caTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kubernetes"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

// selfSigned is template signed by a fresh key, PEM-encoded.
func selfSigned(t *testing.T, template *x509.Certificate) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testDocument(t *testing.T) Document {
	t.Helper()
	return Document{
		SchemaVersion: SchemaVersion,
		CDS: cmdsutil.CDS{
			Address:      "cds.acme.example:8443",
			Measurements: testCDSPin(t, cdsConfig(t, "192.168.0.0/16")),
			PinFloor:     1,
		},
		TLSSAN: "c8s.acme.example",
		Router: &launchconfig.Router{Hostnames: []string{"api.acme.example"}, ACMEEmail: "ops@acme.example"},
		Kubernetes: Kubernetes{
			APIServer:     "acme.k8s.example:443",
			CACertificate: selfSigned(t, caTemplate()),
			PodCIDR:       "10.52.0.0/16",
			ServiceCIDR:   "10.53.0.0/16",
			ClusterDNS:    "10.53.0.10",
		},
	}
}

func marshalDocument(t *testing.T, doc Document) []byte {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseReturnsTheDocument(t *testing.T) {
	want := testDocument(t)
	got, err := Parse(marshalDocument(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if got.CDS != want.CDS || got.Kubernetes != want.Kubernetes {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	if got.Router == nil || len(got.Router.Hostnames) != 1 || got.Router.Hostnames[0] != "api.acme.example" || got.Router.ACMEEmail != "ops@acme.example" {
		t.Fatalf("router = %+v", got.Router)
	}
}

func TestParseLeavesAnAbsentRouterNil(t *testing.T) {
	doc := testDocument(t)
	doc.Router = nil
	data := marshalDocument(t, doc)
	if bytes.Contains(data, []byte("router:")) {
		t.Fatalf("an absent router block was rendered:\n%s", data)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Router != nil {
		t.Fatalf("router = %+v, want none", got.Router)
	}
}

func TestParseAcceptsEachAPIServerForm(t *testing.T) {
	for _, address := range []string{
		"acme.k8s.example:443",
		"kubernetes:6443",
		"10.0.0.1:443",
		"192.168.1.10:65535",
	} {
		doc := testDocument(t)
		doc.Kubernetes.APIServer = address
		if _, err := Parse(marshalDocument(t, doc)); err != nil {
			t.Errorf("apiServer %s: %v", address, err)
		}
	}
}

func TestParseAcceptsEachHostAddressForClusterDNS(t *testing.T) {
	tests := []struct {
		serviceCIDR string
		clusterDNS  string
	}{
		{"10.53.0.0/16", "10.53.0.1"},
		{"10.53.0.0/16", "10.53.255.254"},
		{"10.53.0.0/30", "10.53.0.1"},
		{"10.53.0.0/30", "10.53.0.2"},
	}
	for _, tc := range tests {
		doc := testDocument(t)
		doc.Kubernetes.ServiceCIDR = tc.serviceCIDR
		doc.Kubernetes.ClusterDNS = tc.clusterDNS
		if _, err := Parse(marshalDocument(t, doc)); err != nil {
			t.Errorf("clusterDNS %s in %s: %v", tc.clusterDNS, tc.serviceCIDR, err)
		}
	}
}

func TestParseRefusesEachMalformedField(t *testing.T) {
	ca := selfSigned(t, caTemplate())
	tests := []struct {
		name   string
		change func(*Document)
		want   string
	}{
		{"schema", func(d *Document) { d.SchemaVersion = "c8s-launch/v2" }, "schemaVersion must be c8s-worker/v1"},
		{"cds address without port", func(d *Document) { d.CDS.Address = "cds.acme.example" }, "must be <host>:<port>"},
		{"cds pin binding no configuration", func(d *Document) { d.CDS.Measurements = testDigestOnlyPin(t) }, "binds no launch file"},
		{"cds pin entries disagreeing on node subnets", func(d *Document) {
			d.CDS.Measurements = testCDSPin(t, cdsConfig(t, "192.168.0.0/16"), cdsConfig(t, "172.16.0.0/12"))
		}, "binds another configuration"},
		{"cds pin binding something else", func(d *Document) { d.CDS.Measurements = testCDSPin(t, "kind: Pod\n") }, "the pinned CDS configuration"},
		{"router", func(d *Document) { d.Router = &launchconfig.Router{ACMEEmail: "ops@acme.example"} }, "require router.hostnames"},

		{"api server with a scheme", func(d *Document) { d.Kubernetes.APIServer = "https://acme.k8s.example:443" }, "must not carry a scheme"},
		{"api server with a path", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:443/healthz" }, "must not carry a path"},
		{"api server with userinfo", func(d *Document) { d.Kubernetes.APIServer = "admin@acme.k8s.example:443" }, "must not carry userinfo"},
		{"api server bracketed", func(d *Document) { d.Kubernetes.APIServer = "[acme.k8s.example]:443" }, "must not bracket its host"},
		{"api server ipv6", func(d *Document) { d.Kubernetes.APIServer = "[2001:db8::1]:443" }, "must not bracket its host"},
		{"api server without a port", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example" }, "must be <host>:<port>"},
		{"api server with an empty port", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:" }, "port 1..65535"},
		{"api server port zero", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:0" }, "port 1..65535"},
		{"api server port out of range", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:65536" }, "port 1..65535"},
		{"api server port with a leading zero", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:0443" }, "port 1..65535"},
		{"api server port signed", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:+443" }, "port 1..65535"},
		{"api server with two ports", func(d *Document) { d.Kubernetes.APIServer = "acme.k8s.example:443:443" }, "port 1..65535"},
		{"api server uppercase", func(d *Document) { d.Kubernetes.APIServer = "ACME.k8s.example:443" }, "lowercase DNS hostname"},
		{"api server without a host", func(d *Document) { d.Kubernetes.APIServer = ":443" }, "lowercase DNS hostname"},
		{"api server loopback", func(d *Document) { d.Kubernetes.APIServer = "127.0.0.1:443" }, "unicast IPv4 address"},
		{"api server unspecified", func(d *Document) { d.Kubernetes.APIServer = "0.0.0.0:443" }, "unicast IPv4 address"},
		{"api server multicast", func(d *Document) { d.Kubernetes.APIServer = "224.0.0.1:443" }, "unicast IPv4 address"},

		{"no ca", func(d *Document) { d.Kubernetes.CACertificate = "" }, "must hold a PEM block"},
		{"two cas", func(d *Document) { d.Kubernetes.CACertificate = ca + ca }, "exactly one PEM block"},
		{"ca with trailing bytes", func(d *Document) { d.Kubernetes.CACertificate = ca + "issuer=kubernetes\n" }, "exactly one PEM block"},
		{"ca with leading bytes", func(d *Document) { d.Kubernetes.CACertificate = "issuer=kubernetes\n" + ca }, "nothing before it"},
		{"ca with pem headers", func(d *Document) {
			block, _ := pem.Decode([]byte(ca))
			block.Headers = map[string]string{"Proc-Type": "4,ENCRYPTED"}
			d.Kubernetes.CACertificate = string(pem.EncodeToMemory(block))
		}, "must carry no PEM headers"},
		{"ca of another block type", func(d *Document) {
			block, _ := pem.Decode([]byte(ca))
			block.Type = "PUBLIC KEY"
			d.Kubernetes.CACertificate = string(pem.EncodeToMemory(block))
		}, "must be a PEM CERTIFICATE block"},
		{"ca not a certificate", func(d *Document) {
			d.Kubernetes.CACertificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))
		}, "X.509"},
		{"ca a leaf certificate", func(d *Document) {
			leaf := caTemplate()
			leaf.IsCA = false
			leaf.KeyUsage = x509.KeyUsageDigitalSignature
			d.Kubernetes.CACertificate = selfSigned(t, leaf)
		}, "must be a CA certificate"},

		{"pod range with host bits", func(d *Document) { d.Kubernetes.PodCIDR = "10.52.0.1/16" }, "must be named by its network address, 10.52.0.0/16"},
		{"pod range length with a leading zero", func(d *Document) { d.Kubernetes.PodCIDR = "10.52.0.0/016" }, "must be an IPv4 range"},
		{"pod range a bare address", func(d *Document) { d.Kubernetes.PodCIDR = "10.52.0.0" }, "must be an IPv4 range"},
		{"pod range ipv6", func(d *Document) { d.Kubernetes.PodCIDR = "fd00:52::/64" }, "must be an IPv4 range"},
		{"pod range ipv4-mapped", func(d *Document) { d.Kubernetes.PodCIDR = "::ffff:10.52.0.0/112" }, "must be an IPv4 range"},
		{"pod range the default route", func(d *Document) { d.Kubernetes.PodCIDR = "0.0.0.0/0" }, "reserved range 0.0.0.0/8"},
		{"pod range covering loopback", func(d *Document) { d.Kubernetes.PodCIDR = "64.0.0.0/2" }, "reserved range 127.0.0.0/8"},
		{"pod range loopback", func(d *Document) { d.Kubernetes.PodCIDR = "127.0.0.0/16" }, "reserved range 127.0.0.0/8"},
		{"pod range link-local", func(d *Document) { d.Kubernetes.PodCIDR = "169.254.0.0/16" }, "reserved range 169.254.0.0/16"},
		{"pod range multicast", func(d *Document) { d.Kubernetes.PodCIDR = "239.0.0.0/8" }, "reserved range 224.0.0.0/4"},
		{"service range with host bits", func(d *Document) { d.Kubernetes.ServiceCIDR = "10.53.0.10/16" }, "kubernetes.serviceCIDR"},
		{"service range ipv6", func(d *Document) { d.Kubernetes.ServiceCIDR = "fd00:53::/108" }, "kubernetes.serviceCIDR"},
		{"service range multicast", func(d *Document) { d.Kubernetes.ServiceCIDR = "224.0.0.0/16" }, "reserved range 224.0.0.0/4"},
		{"service range of two addresses", func(d *Document) { d.Kubernetes.ServiceCIDR = "10.53.0.0/31" }, "must be a /30 or wider"},
		{"service range of one address", func(d *Document) { d.Kubernetes.ServiceCIDR = "10.53.0.10/32" }, "must be a /30 or wider"},

		{"pod range covering the service range", func(d *Document) { d.Kubernetes.PodCIDR = "10.52.0.0/15" }, "overlaps kubernetes.serviceCIDR"},
		{"service range inside the pod range", func(d *Document) { d.Kubernetes.ServiceCIDR = "10.52.128.0/24" }, "overlaps kubernetes.serviceCIDR"},
		{"pod range overlapping a node subnet", func(d *Document) {
			d.CDS.Measurements = testCDSPin(t, cdsConfig(t, "10.0.0.0/8"))
		}, "node subnet 10.0.0.0/8 overlaps the cluster range 10.52.0.0/16"},
		{"service range overlapping a node subnet", func(d *Document) {
			d.CDS.Measurements = testCDSPin(t, cdsConfig(t, "192.168.0.0/16", "10.53.4.0/24"))
		}, "node subnet 10.53.4.0/24 overlaps the cluster range 10.53.0.0/16"},

		{"cluster dns outside the service range", func(d *Document) { d.Kubernetes.ClusterDNS = "10.52.0.10" }, "must be inside kubernetes.serviceCIDR"},
		{"cluster dns the network address", func(d *Document) { d.Kubernetes.ClusterDNS = "10.53.0.0" }, "neither the network nor the broadcast address"},
		{"cluster dns the broadcast address", func(d *Document) { d.Kubernetes.ClusterDNS = "10.53.255.255" }, "neither the network nor the broadcast address"},
		{"cluster dns ipv6", func(d *Document) { d.Kubernetes.ClusterDNS = "fd00:53::a" }, "must be an IPv4 address"},
		{"cluster dns a name", func(d *Document) { d.Kubernetes.ClusterDNS = "kube-dns" }, "must be an IPv4 address"},
		{"no cluster dns", func(d *Document) { d.Kubernetes.ClusterDNS = "" }, "kubernetes.clusterDNS"},
		{"no tls san", func(d *Document) { d.TLSSAN = "" }, "tlsSAN"},
		{"a tls san that is an address", func(d *Document) { d.TLSSAN = "192.0.2.1" }, "tlsSAN"},
		{"an uppercase tls san", func(d *Document) { d.TLSSAN = "C8S.acme.example" }, "tlsSAN"},
		{"a tls san the pinned CDS configuration refuses a leaf", func(d *Document) { d.TLSSAN = "other.acme.example" }, "lets a leaf carry"},
		{"a tls san no hostname, under a configuration admitting any", func(d *Document) {
			d.CDS.Measurements = testCDSPin(t, strings.Replace(cdsConfig(t, "192.168.0.0/16"), "leafDNSPatterns: []", `leafDNSPatterns: [".*"]`, 1))
			d.TLSSAN = "c8s.acme.example."
		}, "tlsSAN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := testDocument(t)
			tc.change(&doc)
			_, err := Parse(marshalDocument(t, doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A worker document means exactly what it says: one bounded document, only
// declared fields, each written once, no anchors.
func TestParseRefusesYAMLOutsideTheDocumentRules(t *testing.T) {
	tests := []struct {
		name   string
		change func([]byte) []byte
		want   string
	}{
		{"a role", func(b []byte) []byte { return append(b, "role: worker\n"...) }, "field role not found"},
		{"a signature", func(b []byte) []byte { return append(b, "signature: c2ln\n"...) }, "field signature not found"},
		{"an undeclared kubernetes field", func(b []byte) []byte {
			return bytes.Replace(b, []byte("    podCIDR:"), []byte("    nodeCIDR: 10.0.0.0/8\n    podCIDR:"), 1)
		}, "field nodeCIDR not found"},
		{"a duplicate key", func(b []byte) []byte { return append(b, "schemaVersion: c8s-worker/v1\n"...) }, "duplicate YAML key"},
		{"an anchor and alias", func(b []byte) []byte {
			b = bytes.Replace(b, []byte("podCIDR: 10.52.0.0/16"), []byte("podCIDR: &pods 10.52.0.0/16"), 1)
			return bytes.Replace(b, []byte("serviceCIDR: 10.53.0.0/16"), []byte("serviceCIDR: *pods"), 1)
		}, "anchors and aliases are forbidden"},
		{"a second document", func(b []byte) []byte { return append(b, "---\nschemaVersion: c8s-worker/v1\n"...) }, "exactly one YAML document"},
		{"over the size cap", func(b []byte) []byte { return append(b, "# "+strings.Repeat("x", 1<<20)+"\n"...) }, "1..1048576 bytes"},
		{"nothing", func([]byte) []byte { return nil }, "1..1048576 bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.change(marshalDocument(t, testDocument(t))))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
