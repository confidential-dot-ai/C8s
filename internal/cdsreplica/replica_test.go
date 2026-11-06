package cdsreplica

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// A replica is named as an address, and the port every CDS serves the operator
// on is the default.
func TestAReplicaAddressNamesAHostAndAPort(t *testing.T) {
	for _, tc := range []struct {
		address string
		host    string
		port    uint16
	}{
		{"10.0.0.5", "10.0.0.5", Port},
		{"cds-1.example.org", "cds-1.example.org", Port},
		{"127.0.0.1:8441", "127.0.0.1", 8441},
	} {
		t.Run(tc.address, func(t *testing.T) {
			host, port, err := SplitAddress(tc.address)
			if err != nil || host != tc.host || port != tc.port {
				t.Fatalf("host=%q port=%d error=%v", host, port, err)
			}
		})
	}
	for _, address := range []string{"10.0.0.5:http", "[::1", "a:b:c"} {
		if _, _, err := SplitAddress(address); err == nil {
			t.Fatalf("%q named a replica", address)
		}
	}
	if _, err := ResolveOne(context.Background(), "127.0.0.1:8443"); err != nil {
		t.Fatalf("a replica at a literal address was refused: %v", err)
	}
}

// pin is the pin document naming the test CDS: its image, launched on its
// configuration.
var pin = []byte(testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile))

// serving is a replica that answers a status report and every decree posted
// to it with answer, and counts the requests that reached it.
func serving(
	t *testing.T,
	verifier testutil.VerifierStub,
	answer func(http.ResponseWriter),
) (Replica, *atomic.Int32) {
	t.Helper()
	var reached atomic.Int32
	handler := http.NewServeMux()
	handler.HandleFunc("GET "+StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_ = json.NewEncoder(w).Encode(cdsha.Status{ClusterID: "cl", ID: "member"})
	})
	handler.HandleFunc("POST "+DecreesPath, func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		answer(w)
	})
	server := testutil.NewARMTLSServer(t, handler)
	return Replica{Address: strings.TrimPrefix(server.URL, "https://"), Pin: pin, Verifier: verifier}, &reached
}

func refuse(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(cdsha.Delivered{Intent: "i", Refused: "base version 3 is behind 4"})
}

// A replica reports itself, and the address it answered at is the one a
// decree binding its process records.
func TestStatusIsTheReplicasOwnReport(t *testing.T) {
	r, _ := serving(t, testutil.ApproveAll(), refuse)
	reported, address, err := r.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reported.ID != "member" || address.String() != r.Address {
		t.Fatalf("status %+v at %s, want member at %s", reported, address, r.Address)
	}
}

// Evidence of another launch file is not this cluster's CDS, and nothing is
// sent to it.
func TestAReplicaOfAnotherLaunchFileIsRefusedBeforeAnyRequest(t *testing.T) {
	other := func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		match := true
		result := &teetypes.VerificationResult{Platform: teetypes.PlatformSNP, SignatureValid: true, ReportDataMatch: &match}
		result.Claims.LaunchDigest = testutil.TestMeasurement
		binding := runtimemeasure.HostData([]byte("schemaVersion: another-cluster\n"))
		result.Claims.InitData = binding[:]
		return result, nil
	}
	r, reached := serving(t, other, refuse)
	if _, _, err := r.PostDecree(context.Background(), cdsdecree.Signed{}); err == nil {
		t.Fatal("posted to a replica of another launch file")
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d requests reached a replica that failed verification", n)
	}
}

// A pin document that binds no launch file names no one CDS.
func TestAPinBindingNoLaunchFileIsRefused(t *testing.T) {
	r, reached := serving(t, testutil.ApproveAll(), refuse)
	r.Pin = []byte(`{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + testutil.TestMeasurement + `"}]}`)
	if _, _, err := r.Status(context.Background()); err == nil {
		t.Fatal("read a replica pinned by its image alone")
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d requests reached the replica", n)
	}
}

// The cluster's refusal is its answer to a decree, and an answer that is not
// one is an error.
func TestADecreeTheClusterRefusesIsAnAnswer(t *testing.T) {
	r, _ := serving(t, testutil.ApproveAll(), refuse)
	delivered, _, err := r.PostDecree(context.Background(), cdsdecree.Signed{})
	if err != nil || delivered.Refused == "" {
		t.Fatalf("delivered %+v, error %v; want the refusal as the answer", delivered, err)
	}
	failing, _ := serving(t, testutil.ApproveAll(), func(w http.ResponseWriter) {
		http.Error(w, "leader unknown", http.StatusServiceUnavailable)
	})
	if _, _, err := failing.PostDecree(context.Background(), cdsdecree.Signed{}); err == nil {
		t.Fatal("a 503 answer was taken as delivered")
	}
}
