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

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

func TestPodNetworkMTUBoundsAndCaps(t *testing.T) {
	for _, tc := range []struct{ link, route, want int }{
		{1400, 0, 1400}, {1500, 0, 1500}, {9000, 0, 1500},
		{1500, 1400, 1400}, {1400, 1450, 1400}, {9000, 9000, 1500},
		{68, 0, 68}, {1500, 68, 68}, {65535, 0, 1500},
		{0, 0, 0}, {67, 0, 0}, {-1, 0, 0}, {65536, 0, 0},
		{1500, -1, 0}, {1500, 67, 0}, {1500, 65536, 0},
	} {
		mtu, err := podNetworkMTU(tc.link, tc.route)
		if mtu != tc.want || (err == nil) != (tc.want != 0) {
			t.Errorf("link=%d route=%d: got %d, %v; want %d", tc.link, tc.route, mtu, err, tc.want)
		}
	}
}

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
	for _, path := range []string{PublicDir, PodDir, nriPolicyPath, podUnmanagedLinks} {
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
	if err := prepare(root, podDocument(t), func() (int, error) { calls++; return 1400, nil }); err != nil {
		t.Fatal(err)
	}
	assertPreparedCNI(t, root, 1400)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(baked, after) || calls != 1 {
		t.Fatalf("baked template changed or lookup count differs: %v, calls=%d", err, calls)
	}
}

func TestPreparePodRejectsNetworkBeforePublishing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mtu    int
		err    error
		config string
	}{
		{name: "missing route", err: errors.New("no default route")},
		{name: "invalid MTU", mtu: 0},
		{name: "uncapped MTU", mtu: 9000},
		{name: "invalid baked CNI", mtu: 1400, config: "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := preparePodRoot(t)
			if tc.config != "" {
				writeInput(t, root, bakedPodCNIPath, []byte(tc.config))
			}
			if err := prepare(root, podDocument(t), func() (int, error) { return tc.mtu, tc.err }); err == nil {
				t.Fatal("accepted unusable Pod network")
			}
			assertNoPodOutputs(t, root)
		})
	}
}

func TestPrepareNodesNeverDiscoversPodNetwork(t *testing.T) {
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		root := prepareRoot(t)
		if err := prepare(root, document(t, role), func() (int, error) {
			t.Fatal("node role consulted Pod networking")
			return 0, nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, PodDir)); !os.IsNotExist(err) {
			t.Fatalf("node role published Pod networking: %v", err)
		}
	}
}

func TestRenderPodNetworkRejectsCompetingOrMalformedTemplates(t *testing.T) {
	for _, data := range []string{
		`null`, `{}`, `{"plugins":null}`, `{"plugins":[null]}`,
		`{"plugins":[{},{}]}`, `{"plugins":[{"type":"other","bridge":"c8spod0"}]}`,
		`{"plugins":[{"type":"bridge","bridge":"other"}]}`,
		`{"plugins":[{"type":"bridge","bridge":"c8spod0","mtu":1500}]}`,
	} {
		if _, err := renderPodNetwork([]byte(data), 1400); err == nil {
			t.Errorf("accepted competing or malformed template: %s", data)
		}
	}
}
