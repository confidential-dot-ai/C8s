//go:build !c8s_node

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// writeComputedValues turns the computed tree into a real values.yaml file that
// helm can read back — install passes it as -f instead of inline --set flags.
func TestWriteComputedValuesProducesReadableFile(t *testing.T) {
	path, err := writeComputedValues(map[string]any{
		"image":   map[string]any{"repository": "ghcr.io/x/c8s-operator"},
		"volumed": map[string]any{"enabled": true},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read computed values: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("computed values is not valid yaml: %v\n%s", err, data)
	}
	if got["image"].(map[string]any)["repository"] != "ghcr.io/x/c8s-operator" {
		t.Errorf("repository not in computed values: %#v", got["image"])
	}
	if got["volumed"].(map[string]any)["enabled"] != true {
		t.Errorf("volumed.enabled should be bool true: %#v", got["volumed"])
	}
}

// ta.operatorKeys carries the key bundle's CONTENT, not its path: regression
// test for the operator-keys ConfigMap that shipped a filesystem path.
func TestBuildComputedValuesReadsTheOperatorKeys(t *testing.T) {
	resetCLIState(t)
	installOperatorKeys = writeTestOperatorKeys(t)
	values, err := buildComputedValues(nil)
	if err != nil {
		t.Fatalf("buildComputedValues: %v", err)
	}
	keys, _ := values["ta"].(map[string]any)["operatorKeys"].(string)
	if keys == installOperatorKeys || !strings.Contains(keys, "BEGIN PUBLIC KEY") {
		t.Fatalf("ta.operatorKeys = %q, want the PEM content of %s", keys, installOperatorKeys)
	}
	installOperatorKeys = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := buildComputedValues(nil); err == nil {
		t.Fatal("expected an error for --operator-keys naming a missing file")
	}
}

// writeTestOperatorKeys writes a real EC public-key PEM to a temp file (the
// builder validates it parses) and returns its path.
func writeTestOperatorKeys(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	path := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// computedValuesFile is a computed values tree where helm's last -f reads it.
func computedValuesFile(t *testing.T, tree map[string]any) string {
	t.Helper()
	out, err := yaml.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallTrustAuthorityValuesMerge(t *testing.T) {
	resetCLIState(t)
	pin, err := os.ReadFile(pinnedTAPinFile(t))
	if err != nil {
		t.Fatal(err)
	}
	installValues = []string{
		computedValuesFile(t, valuesAtPath("ta.address", "first.example:8443")),
		computedValuesFile(t, valuesAtPath("ta.measurementsConfig", string(pin))),
		computedValuesFile(t, valuesAtPath("ta.address", "last.example:8443")),
	}
	if err := taPreflight("", "", installValues); err != nil {
		t.Fatal(err)
	}
	resolved, cleanup, err := resolveTAPin(installValues)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	if doc, err := os.ReadFile(resolved.path); err != nil || string(doc) != string(pin) {
		t.Fatalf("resolved pin must be the values file's document: %v", err)
	}
	values, err := buildComputedValues(nil)
	if err != nil {
		t.Fatal(err)
	}
	if url, err := installTAURL(values); err != nil || url != "https://last.example:8443" {
		t.Fatalf("resolved endpoint = %s, %v", url, err)
	}
}

func TestInstallTrustAuthorityOverridesLegacyValues(t *testing.T) {
	resetCLIState(t)
	installValues = []string{
		computedValuesFile(t, valuesAtPath("cds.address", "legacy.example:8443")),
		computedValuesFile(t, valuesAtPath("cds.measurementsConfig", "legacy pin")),
		computedValuesFile(t, valuesAtPath("cds.operatorKeys", "legacy keys")),
	}
	installTAAddress = "replacement.example:8443"
	installTAPin = pinnedTAPinFile(t)
	values, err := buildComputedValues(nil)
	if err != nil {
		t.Fatal(err)
	}
	if values["cds"] != nil {
		t.Fatal("the Helm overlay must clear the legacy block")
	}
	ta, err := trustAuthorityValues(values)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile(installTAPin)
	if err != nil {
		t.Fatal(err)
	}
	if ta["address"] != installTAAddress || ta["measurementsConfig"] != string(pin) || ta["operatorKeys"] != "legacy keys" {
		t.Fatal("expected the explicit endpoint and pin together with the legacy operator keys")
	}

	installValues = append(installValues, computedValuesFile(t, valuesAtPath("ta.address", "ambiguous.example:8443")))
	if err := taPreflight(installTAAddress, installTAPin, installValues); err == nil || !strings.Contains(err.Error(), "ta and cds contain different values") {
		t.Fatalf("preflight must reject conflicts before applying explicit overrides, got %v", err)
	}
}
