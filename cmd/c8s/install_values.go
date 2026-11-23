//go:build !c8s_node

package main

import (
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/helmchart"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

func taValuesFromFiles(files []string) (map[string]string, bool, error) {
	tree := map[string]any{}
	for _, file := range files {
		overlay, err := decodeValuesFile(file)
		if err != nil {
			return nil, false, err
		}
		helmchart.MergeValues(tree, overlay)
	}
	values, err := trustAuthorityValues(tree)
	return values, tree["cds"] != nil, err
}

// The address, pin and operator keys come from one Helm values block.
func trustAuthorityValues(tree map[string]any) (map[string]string, error) {
	ta, err := readTrustAuthorityBlock(tree, "ta")
	if err != nil {
		return nil, err
	}
	legacy, err := readTrustAuthorityBlock(tree, "cds")
	if err != nil {
		return nil, err
	}
	if len(ta) == 0 {
		return legacy, nil
	}
	if len(legacy) != 0 && !maps.Equal(ta, legacy) {
		return nil, fmt.Errorf("ta and cds contain different values for the Trust Authority. Put the address, pin and optional operator keys together under ta")
	}
	return ta, nil
}

func readTrustAuthorityBlock(tree map[string]any, name string) (map[string]string, error) {
	values := map[string]string{}
	if tree[name] == nil {
		return values, nil
	}
	block, ok := tree[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a map of Trust Authority values", name)
	}
	for key, value := range block {
		switch key {
		case "address", "measurementsConfig", "operatorKeys":
		default:
			return nil, fmt.Errorf("unknown Helm value %s.%s", name, key)
		}
		if value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s.%s must be a string", name, key)
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
	ta, legacy, err := taValuesFromFiles(installValues)
	if err != nil {
		return nil, err
	}
	overrides, err := taInstallValues(installTAAddress, installTAPin)
	if err != nil {
		return nil, err
	}
	values := helmchart.MergeValues(map[string]any{}, imagePins)
	if legacy {
		values["cds"] = nil
	}
	if len(ta) != 0 {
		block := make(map[string]any, len(ta))
		for key, text := range ta {
			block[key] = text
		}
		values["ta"] = block
	}
	helmchart.MergeValues(values, overrides)
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
