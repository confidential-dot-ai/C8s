//go:build !c8s_node

package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// validateOperatorKeysFile checks the PEM bundle for cds.operatorKeys holds at
// least one EC public key, so a wrong path or a private-key file fails at
// install time rather than leaving the router without the pinned keys. The
// file itself is handed to helm via --set-file.
func validateOperatorKeysFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read --operator-keys: %w", err)
	}
	if _, err := operatorauth.ParsePublicKeysPEM(data); err != nil {
		return fmt.Errorf("--operator-keys %q: %w", path, err)
	}
	return nil
}

// buildValueArgs assembles the helm --set/--set-string/--set-file value args
// an install sets: the image pins, then the args the install flags set.
func buildValueArgs(imagePins []string) ([]string, error) {
	cdsArgs, err := cdsInstallArgs(installCDSAddress, installCDSPin)
	if err != nil {
		return nil, err
	}
	setArgs := appendVolumedInstallArgs(slices.Concat(imagePins, cdsArgs), installVolumes)
	if installImagePullSecret != "" {
		setArgs = append(setArgs, "--set-string", "imagePullSecret="+installImagePullSecret)
	}
	// --set-file passes the PEM verbatim; --set-string would strvals-parse it,
	// which only works while PEM happens to contain no commas or backslashes.
	if installOperatorKeys != "" {
		if err := validateOperatorKeysFile(installOperatorKeys); err != nil {
			return nil, err
		}
		setArgs = append(setArgs, "--set-file", "cds.operatorKeys="+installOperatorKeys)
	}
	return setArgs, nil
}

// valueArgsToTree turns the flat helm value-flag pairs the builder emits into
// the nested map a values.yaml needs. It handles exactly the arg shapes the
// builder produces — alternating `--set`/`--set-string`/`--set-file` followed
// by a single `key.path=value` token. --set values are typed (true/false/null/
// int coerced; everything else stays a string); --set-string values stay
// strings; --set-file values name a file whose content becomes the value
// verbatim, mirroring helm. Any other flag is an error rather than a silently
// mis-parsed value. Dotted keys nest, except at a backslash-escaped dot; a
// trailing key[n] sets list element n (see setNested) — the one indexed form
// the builder emits. This still does not implement the rest of helm's --set
// grammar (nested indices, comma-joined values) because the builder never
// emits those.
func valueArgsToTree(setArgs []string) (map[string]any, error) {
	root := map[string]any{}
	for i := 0; i < len(setArgs); i += 2 {
		flag := setArgs[i]
		if i+1 >= len(setArgs) {
			return nil, fmt.Errorf("dangling %s with no key=value", flag)
		}
		kv := setArgs[i+1]
		before, after, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("malformed value arg %q (no '=')", kv)
		}
		path, raw := before, after
		var value any
		switch flag {
		case "--set":
			value = coerce(raw, true)
		case "--set-string":
			value = raw
		case "--set-file":
			content, err := os.ReadFile(raw)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", flag, path, err)
			}
			value = string(content)
		default:
			return nil, fmt.Errorf("unsupported value flag %q (want --set, --set-string, or --set-file)", flag)
		}
		segments, err := valuePath(path)
		if err != nil {
			return nil, err
		}
		if err := setNested(root, segments, value); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// coerce mirrors helm's --set vs --set-string typing: --set-string keeps the
// raw string; --set coerces bool/int the way helm's strvals does, so
// `volumed.enabled=true` becomes a real bool.
func coerce(raw string, typed bool) any {
	if !typed {
		return raw
	}
	switch raw {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return n
	}
	return raw
}

// valuePath splits a --set key at each dot that no backslash escapes. A key
// whose last segment is a dangling escape names nothing, so it is an error.
func valuePath(key string) ([]string, error) {
	var path []string
	pending := ""
	for _, piece := range strings.Split(key, ".") {
		if escaped, ok := strings.CutSuffix(piece, `\`); ok {
			pending += escaped + "."
			continue
		}
		path = append(path, pending+piece)
		pending = ""
	}
	if pending != "" {
		return nil, fmt.Errorf("value key %q ends in a backslash", key)
	}
	return path, nil
}

// setNested writes value at the dotted path, creating intermediate maps. A
// conflict (a path segment already holding a non-map value) is an error rather
// than a silent overwrite, since it would mean two builder args disagree.
func setNested(m map[string]any, path []string, value any) error {
	for i, seg := range path {
		if i == len(path)-1 {
			// A trailing key[n] sets element n of a list (helm --set list
			// syntax, e.g. nriImagePolicy.mesh.clusterRanges[0]=…).
			// setListElem grows the list as needed.
			if key, idx, ok := parseListIndex(seg); ok {
				return setListElem(m, strings.Join(path, "."), key, idx, value)
			}
			// A '[' that is not a clean trailing key[n] is outside the grammar
			// this parser handles. Fail loudly rather than key on the raw
			// segment, so a mis-emitting builder can't silently write a bogus
			// key (the test-only grammar guard can't catch that at runtime).
			if strings.ContainsRune(seg, '[') {
				return fmt.Errorf("value path %q: segment %q is not a valid key or key[n] list index", strings.Join(path, "."), seg)
			}
			m[seg] = value
			return nil
		}
		// An inner key[n] descends into element n of a list of maps, as an
		// allowlist entry's containers[0].digest does.
		if key, idx, ok := parseListIndex(seg); ok {
			list, isList := m[key].([]any)
			if _, set := m[key]; set && !isList {
				return fmt.Errorf("value path %q conflicts with an existing non-list at %q", strings.Join(path, "."), key)
			}
			for len(list) <= idx {
				list = append(list, nil)
			}
			child, ok := list[idx].(map[string]any)
			if !ok {
				if list[idx] != nil {
					return fmt.Errorf("value path %q conflicts with an existing scalar at %q", strings.Join(path, "."), seg)
				}
				child = map[string]any{}
				list[idx] = child
			}
			m[key] = list
			m = child
			continue
		}
		if strings.ContainsRune(seg, '[') {
			return fmt.Errorf("value path %q: segment %q is not a valid key or key[n] list index", strings.Join(path, "."), seg)
		}
		child, ok := m[seg].(map[string]any)
		if !ok {
			if _, set := m[seg]; set {
				return fmt.Errorf("value path %q conflicts with an existing scalar at %q", strings.Join(path, "."), seg)
			}
			child = map[string]any{}
			m[seg] = child
		}
		m = child
	}
	return nil
}

// parseListIndex splits a trailing "key[n]" segment into (key, n). ok is false
// for a plain key (no brackets). Only a well-formed non-negative index matches.
func parseListIndex(seg string) (key string, idx int, ok bool) {
	open := strings.IndexByte(seg, '[')
	if open <= 0 || !strings.HasSuffix(seg, "]") {
		return "", 0, false
	}
	n, err := strconv.Atoi(seg[open+1 : len(seg)-1])
	if err != nil || n < 0 {
		return "", 0, false
	}
	return seg[:open], n, true
}

// setListElem sets element idx of the []any at m[key], growing it with nils to
// length idx+1. Mirrors helm: repeated key[i] pairs build the list.
func setListElem(m map[string]any, fullPath, key string, idx int, value any) error {
	list, ok := m[key].([]any)
	if !ok {
		if existing, set := m[key]; set && existing != nil {
			return fmt.Errorf("value path %q conflicts with an existing non-list at %q", fullPath, key)
		}
		list = []any{}
	}
	for len(list) <= idx {
		list = append(list, nil)
	}
	list[idx] = value
	m[key] = list
	return nil
}
