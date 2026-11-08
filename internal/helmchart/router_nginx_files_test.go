package helmchart

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const routerNginxConfigMap = "c8s-router-nginx"

// c8s-lib's nginx files are byte for byte the ones the worker image installs:
// the baked render's nginx ConfigMap.
func TestLibRouterNginxFilesAreTheWorkerImages(t *testing.T) {
	t.Parallel()
	out, err := helmTemplateBakedNode(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	rendered := renderedConfigMap(t, out, routerNginxConfigMap).Data
	dir := filepath.Join("lib", "files", "router-nginx")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != rendered[e.Name()] {
			t.Errorf("%s differs from the baked render's", e.Name())
		}
	}
	if want := slices.Sorted(maps.Keys(rendered)); !slices.Equal(names, want) {
		t.Errorf("c8s-lib holds %v, the baked render %v", names, want)
	}
}
