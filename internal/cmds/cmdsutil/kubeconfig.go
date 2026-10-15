package cmdsutil

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// StaticKubeconfig loads only the explicitly selected file and refuses
// authentication plugins before any transport or client is constructed. A
// kubeconfig is credential data, not authorization to execute more code.
func StaticKubeconfig(filename string) (*rest.Config, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", filename)
	if err != nil {
		return nil, err
	}
	if cfg.ExecProvider != nil || cfg.AuthProvider != nil {
		return nil, fmt.Errorf("kubeconfig authentication plugins are not supported; use static credentials")
	}
	return cfg, nil
}
