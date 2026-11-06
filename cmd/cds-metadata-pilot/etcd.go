package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/metadataha"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
)

type etcdService struct {
	*metadataha.Service
	backend *metadataha.Etcd
}

func (s *etcdService) Close() { s.Service.Close(); s.backend.Close() }

func openEtcd(configs []metadatapilot.ClusterConfig, endpoints, clusterID, caFile, certFile, keyFile string) (*etcdService, error) {
	ca, err := privateFile(caFile, 32<<10)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid dedicated etcd root CA")
	}
	cert, err := privateFile(certFile, 32<<10)
	if err != nil {
		return nil, err
	}
	key, err := privateFile(keyFile, 32<<10)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("invalid dedicated etcd client identity")
	}
	backend, err := metadataha.NewEtcd(metadataha.EtcdConfig{Endpoints: strings.Split(endpoints, ","), ClusterID: clusterID,
		TLS: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}})
	if err != nil {
		return nil, err
	}
	service, err := metadataha.New(configs, backend)
	if err != nil {
		backend.Close()
		return nil, err
	}
	return &etcdService{Service: service, backend: backend}, nil
}
