package nriimagepolicy

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

// A pod CVM's secrets client holds CDS to the launch pins until the node has
// followed the replica set's chain, then to the builds the chain accepts:
// after the floor is raised past the launch build it reaches the new build
// and refuses the old.
func TestPodSecretsClientFollowsTheChainPins(t *testing.T) {
	as := mockapi.New(t)
	measA, measB := strings.Repeat("a1", 48), strings.Repeat("b2", 48)
	pinsDoc := func(meas string) []byte {
		return []byte(`{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds-` + strconv.Itoa(len(meas)) + `","measurement":"` + meas + `","launch_file":"launch"}]}`)
	}
	dir := t.TempDir()
	launch, followed := filepath.Join(dir, "launch.json"), filepath.Join(dir, "chain.json")
	for path, doc := range map[string][]byte{launch: pinsDoc(measA), followed: pinsDoc(measB)} {
		if err := os.WriteFile(path, doc, 0o644); err != nil {
			t.Fatal(err)
		}
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

	chain := &chainPins{path: followed}
	client, err := cdsHTTPClientWithLeaf(pullConfig{CDSMeasurementsConfig: launch, AttestationApiURL: as.URL(), Timeout: 5 * time.Second}, testClusterDNS, chain, nil)
	if err != nil {
		t.Fatal(err)
	}
	reaches := func(meas string) bool {
		verdict := mockapi.PassingVerdict(meas)
		binding := runtimemeasure.HostData([]byte("launch"))
		verdict.Claims.InitData = binding[:]
		as.SetVerdict(verdict)
		client.CloseIdleConnections()
		resp, err := client.Get("https://" + l.Addr().String() + "/")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil
	}
	if !reaches(measA) || reaches(measB) {
		t.Fatal("before the chain is followed, the client must reach the launch build and no other")
	}
	chain.known = testState(t)
	if !reaches(measB) {
		t.Fatal("after the chain is followed, the client does not reach the build it accepts")
	}
	if reaches(measA) {
		t.Fatal("after the chain is followed, the client still reaches the evicted launch build")
	}
}
