package cds

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// A configuration with no replica set serves its cluster from this process:
// the stores and the mesh CA are its own, so it serves them from its start.
func TestAConfigurationWithoutAReplicaSetServesTheClusterAlone(t *testing.T) {
	cfg, state := singletonRunConfig(t, attestingAPI(t))

	back, err := newBackend(context.Background(), cfg, state)
	if err != nil {
		t.Fatalf("newBackend = %v", err)
	}
	defer back.Stop()
	if !back.Ready() {
		t.Error("the CDS of a cluster with no replica set does not serve the state it holds")
	}
}

// A configuration naming a replica set serves the cluster as one replica of
// it, in every build: the CDS image an operator launches is the release.
func TestAConfigurationWithAReplicaSetJoinsTheCluster(t *testing.T) {
	cfg, state := replicatedRunConfig(t, attestingAPI(t))
	cfg.host = "127.0.0.1"
	cfg.port = freePort(t)

	ctx, stopJoining := context.WithCancel(context.Background())
	defer stopJoining()
	joined := startBackend(t, ctx, cfg, state)

	base := "https://" + clientAddress(cfg)
	client := armTLSClient(nil)
	waitForReplica(t, client, base)
	// The replica entry of this configuration answers nothing, so this
	// replica joins no cluster: it reports itself and serves no read.
	if code := statusOf(t, client, base+"/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz = %d while this replica joins, want %d", code, http.StatusServiceUnavailable)
	}
	if code := statusOf(t, client, base+"/ha/status"); code != http.StatusOK {
		t.Errorf("GET /ha/status = %d, want this replica's report of its cluster", code)
	}

	stopJoining()
	if err := <-joined; !errors.Is(err, context.Canceled) {
		t.Fatalf("newBackend = %v, want it to end with the process", err)
	}
}

// startBackend runs the backend until ctx ends, as a joining replica does.
func startBackend(t *testing.T, ctx context.Context, cfg config, state stores) <-chan error {
	t.Helper()
	ended := make(chan error, 1)
	go func() {
		back, err := newBackend(ctx, cfg, state)
		if back != nil {
			back.Stop()
		}
		ended <- err
	}()
	return ended
}

// singletonRunConfig is a CDS VM launched with no replica set.
func singletonRunConfig(t *testing.T, attestationURL string) (config, stores) {
	t.Helper()
	cfg := validRunConfig(t, attestationURL)
	state, err := openStores(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.close)
	return cfg, state
}
