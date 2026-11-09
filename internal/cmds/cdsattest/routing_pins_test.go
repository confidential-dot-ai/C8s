package cdsattest

import (
	"crypto/tls"
	"log/slog"
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

// The router reaches CDS under the pins its node follows, not the pin it was
// started with: once the replica set runs only build B (the floor raised past
// A), the node rewrites its pins in place and the router reaches B and
// refuses A, though --image-policy-file still pins A. Without node pins the
// flag pins CDS.
func TestRouterCDSClientFollowsTheNodePins(t *testing.T) {
	as := mockapi.New(t)
	measA, measB := strings.Repeat("a1", 48), strings.Repeat("b2", 48)
	pinsDoc := func(meas ...string) []byte {
		entries := make([]string, len(meas))
		for i, m := range meas {
			entries[i] = `{"name":"cds-` + strconv.Itoa(i) + `","measurement":"` + m + `","launch_file":"launch"}`
		}
		return []byte(`{"schema_version":"2","tee":"sev-snp","measurements":[` + strings.Join(entries, ",") + `]}`)
	}
	write := func(path string, doc []byte) {
		if err := os.WriteFile(path, doc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	flag, node := filepath.Join(dir, "cds.json"), filepath.Join(dir, "cds-pins.json")
	write(flag, pinsDoc(measA))
	was := nodePinsPath
	nodePinsPath = node
	t.Cleanup(func() { nodePinsPath = was })
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

	client, err := armtls.NewFollowingHTTPClient(routerCDSPins(flag), as.URL())
	if err != nil {
		t.Fatal(err)
	}
	reaches := func(meas string) bool {
		runs(meas)
		client.CloseIdleConnections() // a new handshake, as after a replica moves
		resp, err := client.Get("https://" + l.Addr().String() + "/")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil
	}
	if !reaches(measA) || reaches(measB) {
		t.Fatal("without node pins, the router must reach the build --image-policy-file pins and no other")
	}
	write(node, pinsDoc(measA))
	if !reaches(measA) || reaches(measB) {
		t.Fatal("negative control: under node pins of A, the router must reach A and refuse B")
	}
	write(node, pinsDoc(measB))
	if !reaches(measB) {
		t.Fatal("after the node pinned B alone, the router does not reach B")
	}
	if reaches(measA) {
		t.Fatal("after the node dropped A, the router still reaches A")
	}
}

// The routing engine takes the node's pins: with them mounted, a router
// started without --image-policy-file still builds its CDS client.
func TestRoutingTakesTheNodePins(t *testing.T) {
	node := filepath.Join(t.TempDir(), "cds-pins.json")
	doc := `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + strings.Repeat("a1", 48) + `","launch_file":"launch"}]}`
	if err := os.WriteFile(node, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	was := nodePinsPath
	nodePinsPath = node
	t.Cleanup(func() { nodePinsPath = was })
	cfg := routedRunConfig(t, freePort(t))
	cfg.routing.imagePolicyFile = ""
	if _, err := newRoutingEngine(cfg, NewBindings(), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("newRoutingEngine() = %v, want the node's pins read", err)
	}
}
