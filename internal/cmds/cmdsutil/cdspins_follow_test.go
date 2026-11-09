package cmdsutil

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// A pod client started while the node pinned build A keeps reaching CDS
// after the replica set moves to build B: it reads the node's pins, which the
// node rewrites in place, on every handshake. A build outside them is
// refused.
func TestCDSClientFollowsTheNodePins(t *testing.T) {
	as := mockapi.New(t)
	measA, measB, measC := strings.Repeat("a1", 48), strings.Repeat("b2", 48), strings.Repeat("c3", 48)
	pinsDoc := func(meas ...string) []byte {
		entries := make([]string, len(meas))
		for i, m := range meas {
			entries[i] = `{"name":"cds-` + strconv.Itoa(i) + `","measurement":"` + m + `","launch_file":"launch"}`
		}
		return []byte(`{"schema_version":"2","tee":"sev-snp","measurements":[` + strings.Join(entries, ",") + `]}`)
	}
	path := filepath.Join(t.TempDir(), "cds-pins.json")
	if err := os.WriteFile(path, pinsDoc(measA), 0o644); err != nil {
		t.Fatal(err)
	}
	// The replica attests as whatever build the verdict names.
	runs := func(meas string) {
		verdict := mockapi.PassingVerdict(meas)
		binding := runtimemeasure.HostData([]byte("launch"))
		verdict.Claims.InitData = binding[:]
		as.SetVerdict(verdict)
	}
	serverTLS, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform: "sev-snp", CertTTL: time.Hour,
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), as.URL()),
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	runs(measA)
	client, err := armtls.NewFollowingHTTPClient(CDSPins(path, ImagePolicySource{}), as.URL())
	if err != nil {
		t.Fatal(err)
	}
	get := func() error {
		client.CloseIdleConnections() // every call is a new handshake, as after a replica moves
		resp, err := client.Get("https://" + l.Addr().String() + "/")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(); err != nil {
		t.Fatalf("negative control: a replica of the pinned build: %v", err)
	}
	runs(measB)
	if err := get(); err == nil {
		t.Fatal("a replica of a build the node does not pin was reached")
	}
	// The chain accepts B: the node rewrites its pins in place.
	if err := os.WriteFile(path, pinsDoc(measA, measB), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := get(); err != nil {
		t.Fatalf("after the node pinned B, a replica of B: %v", err)
	}
	runs(measC)
	if err := get(); err == nil {
		t.Fatal("a replica of a build outside the pins was reached")
	}
}
