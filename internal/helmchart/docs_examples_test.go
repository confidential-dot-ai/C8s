package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// helmExample matches a `helm template` command of the chart in a docs code
// block, through its last continuation line.
var helmExample = regexp.MustCompile(`(?m)^helm template c8s internal/helmchart/c8s(?:.* \\\n)*.*$`)

// The operator guide's helm template examples render as written.
func TestOperatorDocHelmTemplateExamples(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm CLI not found")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "operator.md"))
	if err != nil {
		t.Fatal(err)
	}
	examples := helmExample.FindAllString(string(doc), -1)
	if len(examples) == 0 {
		t.Fatal("docs/operator.md has no helm template example")
	}
	for _, example := range examples {
		command, _, _ := strings.Cut(strings.ReplaceAll(example, "\\\n", " "), ">")
		args := strings.Fields(command)[1:]
		// The helm client's simulated cluster may predate the chart's kubeVersion.
		args = append(args, "--kube-version", "1.30.0")
		cmd := exec.Command("helm", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", command, err, tail(out))
		}
	}
}

func tail(out []byte) []byte {
	if len(out) > 2000 {
		return out[len(out)-2000:]
	}
	return out
}
