//go:build integration && linux

package cdsha_test

import (
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
)

var tdxHardware *snpaccept.TDXHardware

func nativeAcceptance() bool { return snpHardware != nil || tdxHardware != nil }
func nativeLaunch() []byte {
	if tdxHardware != nil {
		return tdxHardware.Launch
	}
	return snpHardware.Launch
}
func (c *cluster) hardwareFamily() string {
	if tdxHardware != nil {
		return "tdx"
	}
	return "sev-snp"
}
func (c *cluster) nativeTDXPins() refvalues.ReferenceValues {
	c.t.Helper()
	rv := tdxHardware.Nodes
	rv.Images = slices.Clone(rv.Images)
	for i := range rv.Images {
		rv.Images[i].LaunchFile = slices.Clone(c.config)
	}
	return rv
}
func (c *cluster) cdsPinDocument() string {
	c.t.Helper()
	if tdxHardware == nil {
		return testutil.CDSPinDocument(c.measurement(), string(c.config))
	}
	b, err := refvalues.Render(c.nativeTDXPins())
	if err != nil {
		c.t.Fatal(err)
	}
	return string(b)
}
func (c *cluster) nativeNodeDocument() string {
	c.t.Helper()
	b, err := refvalues.Render(tdxHardware.Nodes)
	if err != nil {
		c.t.Fatal(err)
	}
	return string(b)
}

func runTDXTestMain(m *testing.M) {
	if len(os.Args) != 3 || os.Args[1] != "-test.run=^TestTDXIntegratedRecovery$" || os.Args[2] != "-test.v" {
		panic("fixed TDX acceptance invocation required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	launch, err := os.ReadFile("/run/confai/operator-pubkey")
	if err != nil {
		panic(err)
	}
	tdxHardware, err = snpaccept.OpenTDXHardware(ctx, launch)
	if err != nil {
		panic(err)
	}
	defer tdxHardware.Close()
	releaseProcesses = true
	built = binaries{cds: "/usr/local/bin/c8s", logs: "/run/cds-acceptance/logs"}
	err = snpaccept.ServeTDX(ctx, tdxHardware, func(q snpaccept.Request, relay *snpaccept.Relay) snpaccept.Result {
		snpRequest, snpRelay, snpChecks = q, relay, make(map[string]any)
		server := &http.Server{Addr: "127.0.0.1:9090", Handler: snpaccept.TDXAttestationAPI(tdxHardware, q.IntelCollateral), ReadHeaderTimeout: 5 * time.Second}
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			return snpaccept.Result{Operation: q.Operation, Error: err.Error()}
		}
		go server.Serve(listener)
		defer server.Close()
		code := m.Run()
		out := snpaccept.Result{Operation: q.Operation, Passed: code == 0, Checks: snpChecks, Parameters: q.Parameters}
		if code != 0 {
			out.Error = "CDS acceptance assertion failed; inspect bounded guest diagnostics"
		}
		return out
	})
	if err != nil {
		panic(err)
	}
}

func TestTDXIntegratedRecovery(t *testing.T) {
	if tdxHardware == nil {
		t.Skip("only the immutable TDX acceptance image runs this test")
	}
	testNativeIntegratedRecovery(t)
}

// This compiles the same image tuple used by the receiver, rather than reducing
// TDX identity to MRTD (which is shared by images using the same firmware).
func tdxMeasurement() string                    { return hex.EncodeToString(tdxHardware.Nodes.Images[0].Digest) }
func tdxImagePins(c *cluster) []remote.ImagePin { return c.nativeTDXPins().Images }
