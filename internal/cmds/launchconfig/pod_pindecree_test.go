package launchconfig

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

func podPinCluster(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cluster")
	args := append(bundleArgs(t, dir, "tdx"), "--server-address", "10.0.0.10",
		"--cds-replica", "192.0.2.50", "--cds-voters", "1")
	if err := runBundleCmd(t, args...); err != nil {
		t.Fatal(err)
	}
	return dir
}

func podPinArgs(t *testing.T, cluster, out string) []string {
	t.Helper()
	return []string{"new-pod", "--out", out, "--cluster-id", "demo",
		"--image-manifest", writeManifest(t, "tdx"), "--server-address", "10.0.0.10",
		"--server-public-key", filepath.Join(cluster, serverDir, pubkeyFile),
		"--cds-address", "192.0.2.50:8443", "--cds-image-policy-file", filepath.Join(cluster, "cds-pin.json"),
		"--pod-manifest", writeFile(t, "pod.json", testPodManifest(""))}
}

func readPodPinDecree(t *testing.T, path string) cdsdecree.Signed {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func rewritePodPinDecree(t *testing.T, path string, key *ecdsa.PrivateKey, change func(*cdsdecree.Decree)) string {
	t.Helper()
	decree := readPodPinDecree(t, path).Decree
	change(&decree)
	signed, err := cdsdecree.Sign(decree, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "decree.json", string(data))
}

// The command signs the decree's replacement set and floor under the
// CDS trust the bootstrap policy already binds; the cluster's own policy is
// untouched. cdspins owns the refusal of a decree below the floor.
func TestNewPodPinsTheAppliedDecree(t *testing.T) {
	cluster := podPinCluster(t)
	key := bundleOperatorKey(t, cluster)
	currentPath := writePinDecree(t, cluster, "demo", key, writeRolledCDSManifest(t))
	bootstrapPath := filepath.Join(cluster, "cds-pin.json")
	bootstrapBefore, err := os.ReadFile(bootstrapPath)
	if err != nil {
		t.Fatal(err)
	}
	original, err := refvalues.Parse(bootstrapBefore)
	if err != nil {
		t.Fatal(err)
	}
	want, err := readPodPinDecree(t, currentPath).Decree.CDSPins.WithLaunchFile(original.Images[0].LaunchFile)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "pod")
	if err := runBundleCmd(t, append(podPinArgs(t, cluster, out), "--cds-pin-decree", currentPath)...); err != nil {
		t.Fatal(err)
	}
	doc, _ := readBundleDocument(t, out, podDir)
	pins, err := refvalues.Parse([]byte(doc.CDS.Measurements))
	if err != nil {
		t.Fatal(err)
	}
	if doc.CDS.PinFloor != appliedPinVersion || doc.CDS.Address != "192.0.2.50:8443" || !reflect.DeepEqual(pins, want) {
		t.Fatal("Pod launch did not bind the complete replacement pin set, address and floor")
	}
	if reflect.DeepEqual(pins, original) {
		t.Fatal("Pod launch retained the retired bootstrap image")
	}
	bootstrapAfter, err := os.ReadFile(bootstrapPath)
	if err != nil || string(bootstrapBefore) != string(bootstrapAfter) {
		t.Fatal("building a Pod changed the cluster's bootstrap policy")
	}
}

// A decree is accepted only under the CDS trust the document already binds.
func TestNewPodRefusesADecreeOutsideItsBoundCDSTrust(t *testing.T) {
	cluster := podPinCluster(t)
	key := bundleOperatorKey(t, cluster)
	stranger, _ := testKey(t)
	valid := writePinDecree(t, cluster, "demo", key, writeRolledCDSManifest(t))
	cases := []struct{ name, path, says string }{
		{"another signer", writePinDecree(t, cluster, "demo", stranger, writeRolledCDSManifest(t)), "signature"},
		{"another launch file", rewritePodPinDecree(t, valid, key, func(d *cdsdecree.Decree) {
			d.CDSPins.LaunchFileSHA256 = strings.Repeat("00", 32)
		}), "launch file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "refused")
			err := runBundleCmd(t, append(podPinArgs(t, cluster, out), "--cds-pin-decree", tc.path)...)
			if err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("accepted %s decree: %v", tc.name, err)
			}
			requireAbsent(t, out)
		})
	}
}
