//go:build integration && linux

package cdsha_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/cdsrecovery"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func protectCurrentRecovery(t *testing.T, objects *objectFixture) {
	t.Helper()
	protectRecovery(t, objects)
	f := objects.recovery
	f.currentPolicy = true
	f.wrappingKey = make([]byte, 32)
	if _, err := rand.Read(f.wrappingKey); err != nil {
		t.Fatal(err)
	}
}

func (f *recoveryFixture) closeAuthority() {
	if f.authority != nil {
		f.authority.Close()
		f.authority = nil
	}
	if f.closeReplay != nil {
		f.closeReplay()
		f.closeReplay = nil
	}
}

func (f *recoveryFixture) restoreCurrent(c *cluster, expected cdsrecovery.Identity, record []byte) {
	c.t.Helper()
	objects := c.objectWAL
	var provision cdsobject.Provision
	if err := json.Unmarshal(objects.provision, &provision); err != nil {
		c.t.Fatal(err)
	}
	// Same TLS fixture endpoints and real adapters as the CDS processes. The
	// metadata variant obtains freshness from its separate metadata process.
	config := objects.config
	s3, err := objectwal.NewS3(objectwal.S3Config{Bucket: config.Bucket, Region: config.Region, Endpoint: config.Endpoint, PathStyle: config.PathStyle, HTTPClient: objects.client}, provision.Credentials)
	if err != nil {
		c.t.Fatal(err)
	}
	var store objectwal.Store = s3
	var metadata *metadatapilot.Client
	if m := objects.metadata; m != nil {
		metadata, err = metadatapilot.NewClient(m.endpoint, config.Prefix, provision.MetadataToken, m.client.Transport)
		if err != nil {
			c.t.Fatal(err)
		}
		store = metadatapilot.SplitStore{Objects: s3, Metadata: metadata, HeadKey: config.Prefix + "/head"}
	}
	al, err := allowlist.OpenInMemory()
	if err != nil {
		c.t.Fatal(err)
	}
	f.closeReplay = func() {
		_ = al.Close()
		if metadata != nil {
			metadata.Close()
		}
	}
	parsed, err := cdsconfig.Parse(c.config)
	if err != nil {
		c.t.Fatal(err)
	}
	launch := cdsha.Launch{ClusterID: expected.ClusterID, ConfigSHA256: expected.ConfigSHA256, OperatorKeys: []*ecdsa.PublicKey{&c.operator.PublicKey}, Voters: parsed.HA.Voters}
	// Match restart()'s explicit secret-path limit and the CDS binary's other
	// store defaults. The shared FSM rejects any mismatch at Genesis/restore.
	fsm := cdsha.NewFSM(launch, al, secrets.NewMemoryStore(20000, secrets.DefaultMaxPathsPerHolder, 4096),
		sandboxledger.New(issuer.CapTTL(24*time.Hour, issuer.MaxLeafTTL), 10000))
	if config.DirectState {
		authority, err := cdsrecovery.RestoreCurrentAuthority(c.t.Context(), expected, record, f.capsule, f.wrappingKey, f.verifier,
			cdsrecovery.CurrentRecords{Metadata: metadata, Objects: s3, Launch: launch, Policy: fsm.LocalPolicy(), LaunchFile: c.config})
		if err != nil {
			c.t.Fatal(err)
		}
		f.authority = authority
		return
	}
	authority, err := cdsrecovery.RestoreWALAuthority(c.t.Context(), expected, record, f.capsule, f.wrappingKey, f.verifier,
		cdsrecovery.Replay{Store: store, Machine: fsm, LaunchFile: c.config})
	if err != nil {
		c.t.Fatal(err)
	}
	f.authority = authority
}
