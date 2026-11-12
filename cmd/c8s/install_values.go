//go:build !c8s_node

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// validateOperatorKeysFile returns the PEM bundle for cds.operatorKeys, which
// must hold at least one EC public key, so a wrong path or a private-key file
// fails at install time rather than leaving the router without the pinned keys.
func validateOperatorKeysFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	if _, err := operatorauth.ParsePublicKeysPEM(data); err != nil {
		return nil, fmt.Errorf("--operator-keys %q: %w", path, err)
	}
	return data, nil
}

// buildComputedValues is the values tree an install computes: the image pins,
// then the values the install flags set. No two of those write one path.
func buildComputedValues(imagePins map[string]any) (map[string]any, error) {
	cds, err := cdsInstallValues(installCDSAddress, installCDSPin)
	if err != nil {
		return nil, err
	}
	values := helmchart.MergeValues(map[string]any{}, imagePins)
	helmchart.MergeValues(values, cds)
	if installVolumes {
		// volumed opens a pod's encrypted volumes (docs/volumes.md).
		helmchart.MergeValues(values, map[string]any{"volumed": map[string]any{"enabled": true}})
	}
	if installImagePullSecret != "" {
		values["imagePullSecret"] = installImagePullSecret
	}
	if installOperatorKeys != "" {
		keys, err := validateOperatorKeysFile(installOperatorKeys)
		if err != nil {
			return nil, err
		}
		helmchart.MergeValues(values, map[string]any{"cds": map[string]any{"operatorKeys": string(keys)}})
	}
	return values, nil
}

// valuesAtPath is the tree carrying value at a dotted values path.
func valuesAtPath(path string, value any) map[string]any {
	segments := strings.Split(path, ".")
	for i := len(segments) - 1; i > 0; i-- {
		value = map[string]any{segments[i]: value}
	}
	return map[string]any{segments[0]: value}
}
