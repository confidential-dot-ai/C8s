package allowlist

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// loadComponentSetFile reads a set file: an allowlist document holding exactly
// one set, as a release publishes it, and nothing else.
func loadComponentSetFile(path string) (string, pkgallowlist.ComponentSet, error) {
	var none pkgallowlist.ComponentSet
	doc, err := loadAllowlistFile(path)
	if err != nil {
		return "", none, err
	}
	if len(doc.Workloads) > 0 {
		return "", none, fmt.Errorf("set file %q holds %d workload entr(ies); a set file holds one component set and nothing else", path, len(doc.Workloads))
	}
	if len(doc.Components) != 1 {
		return "", none, fmt.Errorf("set file %q holds %d component sets; a set file holds exactly one", path, len(doc.Components))
	}
	version := slices.Collect(maps.Keys(doc.Components))[0]
	set := doc.Components[version]
	if !set.Current() {
		return "", none, fmt.Errorf("set file %q names a deadline for set %s; retire a set with 'add --retire' or 'retire'", path, version)
	}
	return version, set, nil
}

// parseRetirements reads the VERSION=DEADLINE pairs of --retire.
func parseRetirements(pairs []string, now time.Time) (map[string]pkgallowlist.Deadline, error) {
	deadlines := make(map[string]pkgallowlist.Deadline, len(pairs))
	for _, pair := range pairs {
		version, text, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("--retire %q is not VERSION=DEADLINE", pair)
		}
		deadline, err := parseDeadline(text, now)
		if err != nil {
			return nil, err
		}
		deadlines[version] = deadline
	}
	return deadlines, nil
}

// parseDeadline reads a deadline in the one spelling a document carries, and
// refuses one a set would already have passed.
func parseDeadline(text string, now time.Time) (pkgallowlist.Deadline, error) {
	var deadline pkgallowlist.Deadline
	if err := json.Unmarshal([]byte(strconv.Quote(text)), &deadline); err != nil {
		return deadline, err
	}
	if !deadline.After(now) {
		return deadline, fmt.Errorf("deadline %s has passed; a retiring set ends at its deadline, so write one ahead of now", text)
	}
	return deadline, nil
}
