package cdsattest

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// routeHostsWriter publishes the certificate names of the applied route
// manifest for the acme sidecar, which reads them from a volume only this
// container writes.
func routeHostsWriter(path string) func(*routes.Manifest) error {
	if path == "" {
		return nil
	}
	return func(m *routes.Manifest) error {
		if err := writeRouteHosts(path, m); err != nil {
			return fmt.Errorf("--route-hosts-file: %w", err)
		}
		return nil
	}
}

// writeRouteHosts writes the manifest's host names, one per line in order. A
// pattern names a host suffix rather than a host, so none is written.
func writeRouteHosts(path string, m *routes.Manifest) error {
	var body strings.Builder
	for _, host := range slices.Sorted(maps.Keys(m.Hosts)) {
		body.WriteString(host)
		body.WriteString("\n")
	}
	return fileutil.WriteAtomic(path, []byte(body.String()), 0o644)
}
