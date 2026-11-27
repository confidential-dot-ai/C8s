//go:build !c8s_node

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/helmchart"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

// taValuesFromFiles is the ta block of the -f files, merged as helm merges them.
func taValuesFromFiles(files []string) (map[string]string, error) {
	tree := map[string]any{}
	for _, file := range files {
		overlay, err := decodeValuesFile(file)
		if err != nil {
			return nil, err
		}
		helmchart.MergeValues(tree, overlay)
	}
	return trustAuthorityValues(tree)
}

// trustAuthorityValues is the address, pin and operator keys of a values tree's ta block.
func trustAuthorityValues(tree map[string]any) (map[string]string, error) {
	values := map[string]string{}
	if tree["ta"] == nil {
		return values, nil
	}
	block, ok := tree["ta"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("ta must be a map of Trust Authority values")
	}
	for key, value := range block {
		switch key {
		case "address", "measurementsConfig", "operatorKeys":
		default:
			return nil, fmt.Errorf("unknown Helm value ta.%s", key)
		}
		if value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("ta.%s must be a string", key)
		}
		if text != "" {
			values[key] = text
		}
	}
	return values, nil
}

// validateOperatorKeysFile returns the PEM bundle for ta.operatorKeys, which
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
	ta, err := taInstallValues(installTAAddress, installTAPin)
	if err != nil {
		return nil, err
	}
	values := helmchart.MergeValues(map[string]any{}, imagePins)
	helmchart.MergeValues(values, ta)
	if installTA != nil && installTAPin == "" {
		// A values file is read again by helm: the pin checked is the one
		// the release carries.
		helmchart.MergeValues(values, map[string]any{
			"ta": map[string]any{"measurementsConfig": string(installTA.document)},
		})
	}
	if installVolumes {
		// volumed opens a pod's encrypted volumes (docs/volumes.md).
		helmchart.MergeValues(values, map[string]any{
			"volumed": map[string]any{
				"enabled": true,
			},
		})
	}
	if installImagePullSecret != "" {
		values["imagePullSecret"] = installImagePullSecret
	}
	if installOperatorKeys != "" {
		keys, err := validateOperatorKeysFile(installOperatorKeys)
		if err != nil {
			return nil, err
		}
		helmchart.MergeValues(values, map[string]any{
			"ta": map[string]any{
				"operatorKeys": string(keys),
			},
		})
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
