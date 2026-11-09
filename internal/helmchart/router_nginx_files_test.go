package helmchart

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

const (
	routerNginxConfigMap = "c8s-router-nginx"
	// The directories c8s-lib's files name (c8s.routerWorkerConfigDir and
	// c8s.routerWorkerSettingsDir), which the cloud's one mount replaces.
	workerRouterConfigDir   = "/usr/lib/c8s/router-nginx"
	workerRouterSettingsDir = "/run/c8s-node/router"
)

// The cloud serves c8s-lib's nginx files, the worker image's, with its own
// mount in place of the worker's directories, and stages its own settings
// beside them.
func TestCloudRouterNginxFilesAreTheWorkerImages(t *testing.T) {
	t.Parallel()
	cloud := cloudRouterNginxFiles(t)
	lib := libRouterNginxFiles(t)
	moved := strings.NewReplacer(workerRouterConfigDir, routerConfigDir, workerRouterSettingsDir, routerConfigDir)
	for _, name := range slices.Sorted(maps.Keys(lib)) {
		if cloud[name] != moved.Replace(lib[name]) {
			t.Errorf("the cloud's %s is not c8s-lib's with %s in place of the worker's directories", name, routerConfigDir)
		}
	}
	want := append(slices.Collect(maps.Keys(lib)), "request-body.conf", "tls.conf")
	slices.Sort(want)
	if got := slices.Sorted(maps.Keys(cloud)); !slices.Equal(got, want) {
		t.Errorf("the cloud ConfigMap holds %v, want c8s-lib's files and its settings %v", got, want)
	}
}
