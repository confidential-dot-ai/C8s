package cds

import (
	"fmt"

	utilnet "k8s.io/apimachinery/pkg/util/net"
)

var chooseHostInterface = utilnet.ChooseHostInterface

func resolveListenHost(host string) (string, error) {
	if host != "auto" {
		return host, nil
	}
	ip, err := chooseHostInterface()
	if err != nil {
		return "", fmt.Errorf("--host=auto: select this VM's primary IPv4 address: %w", err)
	}
	if ip.To4() == nil || !ip.IsGlobalUnicast() {
		return "", fmt.Errorf("--host=auto: selected address %q must be a routable IPv4 address", ip)
	}
	return ip.String(), nil
}
