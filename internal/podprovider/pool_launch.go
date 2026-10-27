package podprovider

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func signedDocument(trust trustSpec) (*launchconfig.Document, error) {
	if trust.InitData.Format != launchconfig.SchemaVersion {
		return nil, errors.New("stored launch format is invalid")
	}
	doc, err := launchconfig.Parse(trust.InitData.Document)
	if err != nil {
		return nil, errors.New("stored launch document is invalid")
	}
	block, rest := pem.Decode([]byte(trust.LaunchKey))
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid stored launch public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid stored launch public key")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid stored launch key type")
	}
	if err := operatorauth.VerifyDetached([]*ecdsa.PublicKey{pub}, trust.InitData.Document, string(trust.InitData.Signature)); err != nil {
		return nil, errors.New("stored launch signature does not verify")
	}
	return doc, nil
}

func (c *Config) genericLaunch(name string) (createRequest, error) {
	doc := launchconfig.Document{SchemaVersion: launchconfig.SchemaVersion, ClusterID: c.ClusterID, Role: launchconfig.Pod, Image: c.image, Node: launchconfig.Node{Name: name}, Server: launchconfig.ServerConfig{Address: c.ServerAddress, OperatorPublicKey: c.serverPub}, PodOperatorPublicKey: c.pub}
	data, sig, err := launchconfig.SignDocument(doc, c.key)
	if err != nil {
		return createRequest{}, err
	}
	if len(data) > 64<<10 {
		return createRequest{}, errors.New("generic launch exceeds the Cloud 64 KiB limit")
	}
	return createRequest{Image: c.Image, Size: c.Size, Location: c.Location, Tee: "tdx", Name: name, Count: 1, Labels: map[string]string{"podcvm-provider": c.ProviderID, "podcvm-uid": strings.TrimPrefix(name, "podcvm-")}, Network: networkSpec{PublicIP: c.PublicIP, Ingress: []ingress{{Name: "pod-status", Port: 8443}}}, Readiness: readinessSpec{TCPPorts: []int{}}, Trust: trustSpec{LaunchKey: c.pub, InitData: initData{Format: launchconfig.SchemaVersion, Document: data, Signature: []byte(sig)}}}, nil
}
