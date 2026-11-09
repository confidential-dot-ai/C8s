package nodeservices

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func decodeCNI(t *testing.T, data []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertPreparedCNI(t *testing.T, root string, want int) {
	t.Helper()
	baked, err := os.ReadFile(filepath.Join(root, bakedPodCNIPath))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, podCNIPath))
	if err != nil {
		t.Fatal(err)
	}
	before, after := decodeCNI(t, baked), decodeCNI(t, data)
	before["plugins"].([]any)[0].(map[string]any)["mtu"] = json.Number(strconv.Itoa(want))
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("prepared CNI differs beyond mtu=%d: %s", want, data)
	}
	info, err := os.Stat(filepath.Join(root, podCNIPath))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("prepared CNI permissions: %v, %v", info, err)
	}
}

func assertNoPodOutputs(t *testing.T, root string) {
	t.Helper()
	for _, path := range []string{PublicDir, PodDir, floorConfigPath, podUnmanagedLinks} {
		if _, err := os.Stat(filepath.Join(root, path)); !os.IsNotExist(err) {
			t.Errorf("published %s after rejected network: %v", path, err)
		}
	}
}

func TestPreparePodStagesMTUWithoutChangingTheBakedTemplate(t *testing.T) {
	root := preparePodRoot(t)
	path := filepath.Join(root, bakedPodCNIPath)
	baked, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown fields and large JSON integers must survive rendering unchanged.
	config := decodeCNI(t, baked)
	config["extension"] = json.Number("9007199254740993")
	config["plugins"].([]any)[0].(map[string]any)["extension"] = map[string]any{"enabled": true}
	baked, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	writeInput(t, root, bakedPodCNIPath, baked)
	calls := 0
	if err := preparePodDocument(root, podDocument(t), func() (int, error) { calls++; return 1400, nil }); err != nil {
		t.Fatal(err)
	}
	assertPreparedCNI(t, root, 1400)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(baked, after) || calls != 1 {
		t.Fatalf("baked template changed or lookup count differs: %v, calls=%d", err, calls)
	}
}

// The network is validated before anything is published; a baked template
// that fixes the MTU competes with uplink discovery and is refused.
func TestPreparePodRejectsNetworkBeforePublishing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mtu    int
		err    error
		config string
	}{
		{name: "missing route", err: errors.New("no default route")},
		{name: "uncapped MTU", mtu: 9000},
		{name: "invalid baked CNI", mtu: 1400, config: "{"},
		{name: "baked CNI competes with discovery", mtu: 1400, config: `{"plugins":[{"type":"bridge","bridge":"c8spod0","mtu":1500}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			if tc.config != "" {
				writeInput(t, root, bakedPodCNIPath, []byte(tc.config))
			}
			if err := preparePodDocument(root, podDocument(t), func() (int, error) { return tc.mtu, tc.err }); err == nil {
				t.Fatal("accepted unusable Pod network")
			}
			assertNoPodOutputs(t, root)
		})
	}
}
