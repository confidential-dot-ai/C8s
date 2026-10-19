// Package workloadname defines the grammar of allowlist workload names. It
// has no dependencies so that any verifier can import it.
package workloadname

// MaxLen bounds a name to the Kubernetes label-value length, so the
// confidential.ai/cw selector, an allowlist entry and the matched
// workload extension of a named leaf (pkg/armtls) can all represent it.
const MaxLen = 63

// Valid reports whether name follows the grammar and is at most MaxLen
// bytes: the check the allowlist write path, the admission selector and the
// matched-workload stamp share. A name may still end in '.', '_' or '-' and
// fail Kubernetes label-value validation, which the injection webhook applies
// to the confidential.ai/cw label; tightening the grammar would invalidate
// stored entries.
func Valid(name string) bool {
	return ValidGrammar(name) && len(name) <= MaxLen
}

// ValidGrammar reports whether name is a URL-safe path segment,
// [A-Za-z0-9][A-Za-z0-9._-]*, so it can be used verbatim as a path
// parameter. It does not apply MaxLen.
func ValidGrammar(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case (b == '.' || b == '_' || b == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}
