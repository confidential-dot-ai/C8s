package cdspins

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"gopkg.in/yaml.v3"
)

func nativeLaunch(t *testing.T) []byte {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal(cluster(t, operatorKey(t)), &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "ha")
	nodes, err := refvalues.Format(pinSet(t, []byte("node launch binding"), 0x33))
	if err != nil {
		t.Fatal(err)
	}
	document["workloads"] = `{"schema":"c8s.allowlist/v1","workloads":{}}`
	document["nodes"] = string(nodes)
	document["nodeCIDRs"] = []string{"10.0.0.0/24"}
	document["objectState"] = map[string]any{
		"bucket": "cds-state-test", "key": "clusters/test/current", "region": "us-east-2",
		"expectedBucketOwner": "123456789012", "recoveryAuthority": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"snpMinTCB": map[string]uint8{"bootloader": 12, "tee": 0, "snp": 28, "microcode": 28},
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cdsconfig.Parse(data); err != nil {
		t.Fatal(err)
	}
	return data
}

type mutableNativePins struct{ values refvalues.ReferenceValues }

func (p *mutableNativePins) Current() refvalues.ReferenceValues { return p.values }
func (*mutableNativePins) Generation() uint64                   { return 0 }
func (*mutableNativePins) Refresh() error                       { return nil }

func TestNativePinsRetainVerifierAndRefuseLaunchChanges(t *testing.T) {
	launch := nativeLaunch(t)
	source := &mutableNativePins{values: pinSet(t, launch, 0x11, 0x22)}
	prepared, err := WithNativeVerification(source)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NativeVerifierFor(prepared)
	if err != nil || first == nil {
		t.Fatalf("object-state pins did not select native verification: %v", err)
	}
	for range 3 {
		again, err := WithNativeVerification(prepared)
		if err != nil || again != prepared {
			t.Fatal("prepared source replaced its verifier admission bound")
		}
		native, err := NativeVerifierFor(again)
		if err != nil || native != first {
			t.Fatal("refresh replaced native verifier or approved floor")
		}
	}
	client, err := NewRefreshingHTTPClient(prepared, "")
	if err != nil {
		t.Fatalf("native transport required a remote verdict URL: %v", err)
	}
	client.CloseIdleConnections()
	source.values = pinSet(t, bytes.Replace(launch, []byte("bootloader: 12"), []byte("bootloader: 1"), 1), 0x11)
	if _, err := NativeVerifierFor(prepared); err == nil {
		t.Fatal("a changed pinned launch lowered the retained floor")
	}
}

func TestNativePinsRejectIncompleteFloorsAndMixedLaunches(t *testing.T) {
	launch := nativeLaunch(t)
	missing := bytes.Replace(launch, []byte("tee: 0"), []byte("missing: 0"), 1)
	if _, err := WithNativeVerification(armtls.FixedPins(pinSet(t, missing, 0x11))); err == nil {
		t.Fatal("object mode fell back after an incomplete approved floor")
	}
	mixed := pinSet(t, launch, 0x11, 0x22)
	mixed.Images[1].LaunchFile = []byte(singleCDS)
	if _, err := WithNativeVerification(armtls.FixedPins(mixed)); err == nil {
		t.Fatal("mixed native and legacy launch bindings were accepted")
	}
}

func TestNativePinsPreserveLegacySelectionAndEarlyURLValidation(t *testing.T) {
	legacy := &mutableNativePins{values: pinSet(t, []byte(singleCDS), 0x11)}
	prepared, err := WithNativeVerification(legacy)
	if err != nil || prepared != legacy {
		t.Fatalf("legacy source changed: %v", err)
	}
	if native, err := NativeVerifierFor(prepared); err != nil || native != nil {
		t.Fatalf("legacy source became native: %v", err)
	}
	if _, err := NewRefreshingHTTPClient(prepared, ""); err == nil {
		t.Fatal("legacy client lost construction-time URL validation")
	}
}
