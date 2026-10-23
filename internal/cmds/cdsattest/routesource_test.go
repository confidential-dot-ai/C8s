package cdsattest

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On a node whose enforcer mounts the CDS pins it follows, the route
// manifest client holds CDS to those (re-read on a pin miss) instead of the
// launch-time set --image-policy-file names: a CDS image rollout must not
// cut the router off its routes. Without that mount the flags decide.
func TestRouteSourceClientPrefersTheFollowedPins(t *testing.T) {
	policy, err := os.ReadFile("../../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	launch := filepath.Join(dir, "cds.json")
	if err := os.WriteFile(launch, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	followed := filepath.Join(dir, "router-cds-pins.json")
	orig := followedRouterPins
	followedRouterPins = followed
	t.Cleanup(func() { followedRouterPins = orig })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	api := "unix:///run/nri-image-policy/attestation-api.sock"

	// No followed pins mounted: the launch file pins CDS, statically.
	hc, pinned, err := routeSourceClient(routingConfig{imagePolicyFile: launch}, api, log)
	if err != nil || !pinned {
		t.Fatalf("launch file: %v pinned=%v", err, pinned)
	}
	if _, static := hc.Transport.(*http.Transport); !static {
		t.Fatal("no followed pins, yet the client refreshes")
	}
	// Followed pins mounted: the client follows them (a refreshing transport).
	if err := os.WriteFile(followed, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	hc, pinned, err = routeSourceClient(routingConfig{imagePolicyFile: launch}, api, log)
	if err != nil || !pinned {
		t.Fatalf("followed pins: %v pinned=%v", err, pinned)
	}
	if _, static := hc.Transport.(*http.Transport); static {
		t.Fatal("followed pins mounted, yet the client holds the launch set")
	}
	// A followed file that does not parse fails rather than falling back.
	if err := os.WriteFile(followed, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := routeSourceClient(routingConfig{imagePolicyFile: launch}, api, log); err == nil {
		t.Fatal("an unreadable followed policy fell back to the launch set")
	}
	// Measurement flags (no policy file) ignore the mount: a chart without a
	// baked node names its own pins.
	if _, pinned, err := routeSourceClient(routingConfig{cdsMeasurements: []string{strings.Repeat("ab", 48)}}, api, log); err != nil || !pinned {
		t.Fatalf("measurement pins: %v pinned=%v", err, pinned)
	}
	// Nothing pinned at all is reported, for the caller's development check.
	if _, pinned, err := routeSourceClient(routingConfig{}, api, log); err != nil || pinned {
		t.Fatalf("no pins: %v pinned=%v", err, pinned)
	}
}
