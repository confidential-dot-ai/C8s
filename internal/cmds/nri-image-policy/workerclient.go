package nriimagepolicy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"

	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

func (c *config) workerNodeClient(kubeconfig, nodeName string) (coreclient.CoreV1Interface, error) {
	nodeAPI, err := c.nodeAPIConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := rest.TLSConfigFor(nodeAPI)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil || tlsConfig.GetClientCertificate == nil {
		return nil, fmt.Errorf("worker kubeconfig lacks a client certificate")
	}
	certificate, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		return nil, err
	}
	if certificate == nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("worker kubeconfig has an empty client certificate")
	}
	identity, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	if identity.Subject.CommonName != "system:node:"+nodeName || !slices.Contains(identity.Subject.Organization, "system:nodes") {
		return nil, fmt.Errorf("kubelet credential does not identify the staged worker")
	}
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return certificate, nil
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.DisableKeepAlives = true
	if nodeAPI.Proxy != nil {
		transport.Proxy = nodeAPI.Proxy
	}
	if nodeAPI.Dial != nil {
		transport.DialContext = nodeAPI.Dial
	}
	roundTripper, err := rest.HTTPWrappersForConfig(nodeAPI, transport)
	if err != nil {
		return nil, err
	}
	return coreclient.NewForConfigAndClient(nodeAPI, &http.Client{Transport: roundTripper, Timeout: nodeAPI.Timeout})
}
