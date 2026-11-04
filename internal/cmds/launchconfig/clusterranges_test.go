package launchconfig

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// The generator refuses a node subnet reaching into the cluster's own ranges,
// which it must know without a cluster: the node image's RKE2 configuration
// fixes them, so the two copies are checked against each other here.
func TestClusterRangesMatchTheNodeImage(t *testing.T) {
	data, err := os.ReadFile("../../../images/node-guest/c8s/mkosi.extra/etc/rancher/rke2/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, key := range []string{"cluster-cidr", "service-cidr"} {
		m := regexp.MustCompile(`(?m)^` + key + `:\s*(\S+)$`).FindSubmatch(data)
		if m == nil {
			t.Fatalf("the node image's RKE2 configuration sets no %s", key)
		}
		want = append(want, string(m[1]))
	}
	if !slices.Equal(clusterRanges, want) {
		t.Errorf("clusterRanges = %v, want the node image's %v", clusterRanges, want)
	}
}
