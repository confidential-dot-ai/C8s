//go:build !linux

package nriimagepolicy

import "errors"

// Off Linux there is no nftables namespace to protect, so installing or
// verifying a pod ruleset fails. This keeps `go build` for the macOS CLI
// honest.
var errNoPodRuleset = errors.New("the pod mesh ruleset is only implemented on linux")

func installPodRuleset(podNamespace, meshPolicy, string) error {
	return errNoPodRuleset
}

func verifyPodRuleset(podNamespace, meshPolicy, string) error {
	return errNoPodRuleset
}
