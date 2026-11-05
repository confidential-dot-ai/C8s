package nodeservices

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
)

var update = flag.Bool("update", false, "regenerate testdata/prepare/*.golden")

// goldenFloor is a baked config whose base pins both node placeholders and
// whose mesh policy declares the node image's cluster ranges.
const goldenFloor = `platform: tdx
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      kube-apiserver:
        containers:
          - digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
            command: {policy: any}
            args:
              policy: exact
              argv: ["--advertise-address=${NODE_ADVERTISE_ADDRESS}", "--node-name=${NODE_NAME}", "--secure-port=6443"]
  pull:
    url: https://127.0.0.1:30808
    timeout: 30s
policy:
  mode: fail-closed
  enforce_existing: true
` + meshPolicy + `  cluster_ranges: ["10.52.0.0/16", "10.53.0.0/16"]
`

// A server's and an agent's staged outputs, byte for byte and with their
// modes.
func TestPrepareMatchesTheGoldenOutputs(t *testing.T) {
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent} {
		t.Run(string(role), func(t *testing.T) {
			golden := filepath.Join("testdata", "prepare", string(role)+".golden")
			root := prepareRoot(t)
			writeInput(t, root, "/usr/lib/c8s/image-policy.yaml", []byte(goldenFloor))
			doc := document(t, role)
			doc.Node = launchconfig.Node{Name: "n1", IP: "192.0.2.21"}
			doc.Router = &launchconfig.Router{Hostnames: []string{"api.example.org"}, ACMEEmail: "ops@example.org"}
			if err := PrepareNode(root, doc); err != nil {
				t.Fatal(err)
			}
			got := stagedOutputs(t, root)
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("staged outputs =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

// stagedOutputs lists every file under root's run/c8s-node and etc, in path
// order, each headed by its path and mode.
func stagedOutputs(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(name, "run/c8s-node/") && !strings.HasPrefix(name, "etc/") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "== %s %v ==\n%s", name, info.Mode().Perm(), data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
