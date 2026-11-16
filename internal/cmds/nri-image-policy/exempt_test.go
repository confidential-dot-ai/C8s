package nriimagepolicy

import "testing"

func TestExemptRepositoriesAdmits(t *testing.T) {
	exempt := ExemptRepositories{"kube-system": {
		"mcr.microsoft.com/oss/kubernetes/",
		"mcr.microsoft.com/azurelinux/distroless/base/",
		"mcr.microsoft.com/oss/v2/azure/ip-masq-agent-v2/",
		"*-artifactregistry.gcr.io/gke-release/gke-release/",
		"gke.gcr.io/",
		"docker.io/rancher/",
	}}
	for _, tc := range []struct {
		name      string
		namespace string
		imageRef  string
		want      bool
	}{
		{"a repository under the prefix", "kube-system", "mcr.microsoft.com/oss/kubernetes/kube-proxy:v1.31.0", true},
		{"a deeper path under the prefix", "kube-system", "mcr.microsoft.com/oss/kubernetes/autoscaler/addon-resizer:1.8.23", true},
		{"a digested reference", "kube-system", "gke.gcr.io/kube-proxy@" + pushDigestA, true},
		{"the registry the prefix names alone", "kube-system", "gke.gcr.io/pause:3.10", true},
		{"the prefix's own path as a repository", "kube-system", "mcr.microsoft.com/oss/kubernetes:v1.31.0", true},
		{"a path segment the prefix only starts", "kube-system", "mcr.microsoft.com/oss/kubernetes-csi/azuredisk:v1.33.0", false},
		{"the single repository a prefix names in full", "kube-system", "mcr.microsoft.com/azurelinux/distroless/base:3.0", true},
		{"a sibling of that repository", "kube-system", "mcr.microsoft.com/azurelinux/distroless/base-nonroot:3.0", false},
		{"the masq agent's own repository", "kube-system", "mcr.microsoft.com/oss/v2/azure/ip-masq-agent-v2:v0.1.16-22", true},
		{"a regional mirror the wildcard host names", "kube-system", "us-central1-artifactregistry.gcr.io/gke-release/gke-release/kube-proxy:v1.37.1-gke.1552000", true},
		{"another region's mirror", "kube-system", "europe-west4-artifactregistry.gcr.io/gke-release/gke-release/gke-metrics-collector:1.2.3", true},
		{"a mirror image by tag and digest", "kube-system", "us-central1-artifactregistry.gcr.io/gke-release/gke-release/node_token_broker/init:v1.2.3@" + pushDigestA, true},
		{"a dotted label where the wildcard stands", "kube-system", "us.central1-artifactregistry.gcr.io/gke-release/gke-release/kube-proxy:v1.37.1", false},
		{"the mirror host without that label", "kube-system", "artifactregistry.gcr.io/gke-release/gke-release/kube-proxy:v1.37.1", false},
		{"another path on a regional mirror", "kube-system", "us-central1-artifactregistry.gcr.io/gke-release/kube-proxy:v1.37.1", false},
		{"a registry whose host the prefix only starts", "kube-system", "gke.gcr.io.example.com/kube-proxy:v1.31.0", false},
		{"a short Docker Hub reference the prefix names in full", "kube-system", "rancher/local-path-provisioner:v0.0.31", true},
		{"a repository outside every prefix", "kube-system", "docker.io/library/nginx:1.29", false},
		{"a bare image ID", "kube-system", pushDigestA, false},
		{"a reference that does not parse", "kube-system", "Kube-Proxy:v1", false},
		{"a namespace with no prefixes", "default", "gke.gcr.io/kube-proxy:v1.31.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exempt.Admits(tc.namespace, tc.imageRef); got != tc.want {
				t.Errorf("Admits(%q, %q) = %v, want %v", tc.namespace, tc.imageRef, got, tc.want)
			}
		})
	}
}
