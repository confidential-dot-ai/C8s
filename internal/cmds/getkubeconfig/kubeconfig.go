package getkubeconfig

import (
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// buildKubeconfig assembles a single-context kubeconfig from the issued client
// cert + key, the cluster CA, and the apiserver address. clientcmd serialises
// it, so no input can add or alter a YAML key.
//
// tlsServerName, when non-empty, is emitted as tls-server-name: the operator
// dials the guest at a per-launch IP the apiserver cert has no SAN for, so
// verification is pinned to a stable SAN the image bakes into tls-san
// (c8s-cvm) instead. Without it the kubeconfig would need
// --insecure-skip-tls-verify.
func buildKubeconfig(apiserverURL, contextName, tlsServerName string, clientCertPEM, clientKeyPEM, caPEM []byte) ([]byte, error) {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[contextName] = &clientcmdapi.Cluster{
		Server:                   apiserverURL,
		CertificateAuthorityData: caPEM,
		TLSServerName:            tlsServerName,
	}
	cfg.AuthInfos[contextName] = &clientcmdapi.AuthInfo{
		ClientCertificateData: clientCertPEM,
		ClientKeyData:         clientKeyPEM,
	}
	cfg.Contexts[contextName] = &clientcmdapi.Context{Cluster: contextName, AuthInfo: contextName}
	cfg.CurrentContext = contextName
	return clientcmd.Write(*cfg)
}
