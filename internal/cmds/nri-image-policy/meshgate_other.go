//go:build !linux

package nriimagepolicy

import "errors"

// Off Linux there is no nftables namespace to protect, so a mesh policy fails
// the config load. This keeps `go build` for the macOS CLI honest.
const meshSupported = false

var errNoPodRuleset = errors.New("the pod mesh ruleset is only implemented on linux")

func installPodRuleset(podNamespace, meshPolicy) error {
	return errNoPodRuleset
}

func verifyPodRuleset(podNamespace, meshPolicy) error {
	return errNoPodRuleset
}
