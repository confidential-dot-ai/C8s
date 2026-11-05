package launchconfig

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
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

func podPinArgs(t *testing.T, cluster, out string, generic bool) []string {
	t.Helper()
	args := []string{"new-pod", "--out", out, "--cluster-id", "demo",
		"--image-manifest", writeManifest(t, "tdx"), "--server-address", "10.0.0.10",
		"--server-public-key", filepath.Join(cluster, serverDir, pubkeyFile),
		"--cds-address", "192.0.2.50:8443", "--cds-image-policy-file", filepath.Join(cluster, "cds-pin.json")}
	if generic {
		return append(args, "--generic", "--name", "waiting")
	}
	return append(args, "--pod-manifest", writeFile(t, "pod.json", testPodManifest("")))
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

// The real command signs a replacement set and floor for either boot mode;
// staging and a later generic assignment must retain both without a union.
func TestNewPodPinsTheAppliedDecreeAcrossBootAndAssignment(t *testing.T) {
	cluster := podPinCluster(t)
	key := bundleOperatorKey(t, cluster)
	currentPath := writePinDecree(t, cluster, "demo", key, writeRolledCDSManifest(t))
	olderPath := rewritePodPinDecree(t, writePinDecree(t, cluster, "demo", key, writeCDSManifest(t)), key,
		func(d *cdsdecree.Decree) { d.BaseVersion = appliedPinVersion - 1 })
	older := readPodPinDecree(t, olderPath)
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
	for _, tc := range []struct {
		name    string
		generic bool
	}{{"static", false}, {"generic", true}} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "pod")
			args := append(podPinArgs(t, cluster, out, tc.generic), "--cds-pin-decree", currentPath)
			if err := runBundleCmd(t, args...); err != nil {
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
			pub, err := os.ReadFile(filepath.Join(out, podDir, pubkeyFile))
			if err != nil {
				t.Fatal(err)
			}
			testLoader(t, *doc, string(pub))
			cfg := Config{Platform: doc.Image.Platform, RootDir: t.TempDir(),
				DocumentPath: filepath.Join(out, podDir, documentFile), SignaturePath: filepath.Join(out, podDir, signatureFile)}
			if err := Stage(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			staged, err := LoadStaged(cfg.path(DefaultStagedPath))
			if err != nil {
				t.Fatal(err)
			}
			if staged.CDS != doc.CDS {
				t.Fatal("signature-verified staging lost the CDS floor or pin set")
			}
			if tc.generic {
				assigned, err := AssignedPod(staged, []byte(testPodManifest("")), []byte(emptyPodEntries), []byte("[]"))
				if err != nil {
					t.Fatal(err)
				}
				if assigned.CDS != doc.CDS || staged.Pod != nil || staged.Workloads != "" {
					t.Fatal("assignment changed the generic boot's CDS trust or workload authority")
				}
			}
			for _, attested := range []bool{false, true} {
				// Withholding pinned replicas must not let an older signed
				// decree restore the retired image over the fallback channel.
				for _, floor := range []uint64{staged.CDS.PinFloor, 0} {
					source, err := cdspins.New(cdspins.Config{
						Bootstrap: pins, Floor: floor, StateFile: filepath.Join(t.TempDir(), "pins.json"),
						Attested: func(context.Context, refvalues.ReferenceValues) (*cdsdecree.Signed, error) {
							if attested {
								return &older, nil
							}
							return nil, errors.New("pinned replica unavailable")
						},
						Fetch: func(context.Context) (*cdsdecree.Signed, error) { return &older, nil },
					})
					if err != nil {
						t.Fatal(err)
					}
					err = source.Refresh()
					version, held := source.Version()
					if floor != 0 {
						if err == nil || !strings.Contains(err.Error(), "below this node's floor") || held || !reflect.DeepEqual(source.Current(), pins) {
							t.Fatalf("older decree changed protected pins (attested=%t): %v", attested, err)
						}
					} else if err != nil || !held || version != appliedPinVersion-1 || reflect.DeepEqual(source.Current(), pins) {
						t.Fatalf("zero-floor control did not accept the valid older decree (attested=%t): %v", attested, err)
					}
				}
			}
		})
	}
	bootstrapAfter, err := os.ReadFile(bootstrapPath)
	if err != nil || string(bootstrapBefore) != string(bootstrapAfter) {
		t.Fatal("building a Pod changed the cluster's bootstrap policy")
	}
}

func TestNewPodRefusesADecreeOutsideItsBoundCDSTrust(t *testing.T) {
	cluster := podPinCluster(t)
	key := bundleOperatorKey(t, cluster)
	stranger, _ := testKey(t)
	valid := writePinDecree(t, cluster, "demo", key, writeRolledCDSManifest(t))
	cases := []struct{ name, path, says string }{
		{"another signer", writePinDecree(t, cluster, "demo", stranger, writeRolledCDSManifest(t)), "signature"},
		{"another cluster", writePinDecree(t, cluster, "elsewhere", key, writeRolledCDSManifest(t)), "cluster"},
		{"another launch file", rewritePodPinDecree(t, valid, key, func(d *cdsdecree.Decree) {
			d.CDSPins.LaunchFileSHA256 = strings.Repeat("00", 32)
		}), "launch file"},
		{"not a pin decree", rewritePodPinDecree(t, valid, key, func(d *cdsdecree.Decree) {
			d.Kind, d.CDSPins, d.Voters = cdsdecree.SetVoters, nil, 1
		}), "pins no CDS image"},
		{"malformed", writeFile(t, "broken.json", "{"), "pin decree"},
		{"missing", filepath.Join(t.TempDir(), "missing.json"), "pin decree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, generic := range []bool{false, true} {
				out := filepath.Join(t.TempDir(), "refused")
				err := runBundleCmd(t, append(podPinArgs(t, cluster, out, generic), "--cds-pin-decree", tc.path)...)
				if err == nil || !strings.Contains(err.Error(), tc.says) {
					t.Fatalf("generic=%t: accepted %s decree: %v", generic, tc.name, err)
				}
				requireAbsent(t, out)
			}
		})
	}
}
