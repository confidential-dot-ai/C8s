//go:build !c8s_node

package worker

import (
	"bytes"
	_ "embed"
	"text/template"
)

//go:embed controlplane.yaml
var controlPlaneObjects string

// ControlPlaneObjects are what a cluster of workers holds for them beyond c8s's
// chart, its kube-dns Service at doc's clusterDNS.
func ControlPlaneObjects(doc *Document) ([]byte, error) {
	tmpl, err := template.New("control-plane").Option("missingkey=error").Parse(controlPlaneObjects)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, struct{ ClusterDNS string }{doc.Kubernetes.ClusterDNS}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
