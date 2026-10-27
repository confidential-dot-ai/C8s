package nriimagepolicy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
)

// bakedNodeConfig is a node image's config as the chart renders it: every
// node injects credential clients (workload_claims.socket_dir).
const bakedNodeConfig = `platform: tdx
allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      system:
        containers:
          - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
            command: {policy: any}
            args: {policy: any}
  pull:
    url: https://127.0.0.1:30808
    interval: 30s
    timeout: 30s
    attestation_api_url: unix:///run/attest.sock
    cds_measurements: []
policy:
  mode: fail-closed
  enforce_existing: true
workload_claims:
  socket_dir: /run/c8s-enforcer-inventory
  cds_node_port: 30808
mesh:
  exempt_namespaces: [kube-system]
  resolver: "10.53.0.10"
  capture: {outbound: 15001, inbound: 15006, health: 15021}
  roles:
    - name: mesh
      uid: 1337
`

const bakedCDSFloor = `{"schema":"c8s.allowlist/v1","workloads":{"cds-ha-replica":{"containers":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","command":{"policy":"exact","argv":["/c8s","cds"]},"args":{"policy":"exact","argv":["--ha-config=/run/c8s-node/cds-ha.json"]}}]}}}`

const bakedSeed = `{"schema":"c8s.allowlist/v1","workloads":{"operator":{"containers":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`

// Every role of an HA cluster stages a config the plugin starts under. A
// cds-role node injects credential clients like any other node, so it must
// pin CDS too: without pins the plugin refuses to start, and containerd,
// which requires the plugin, creates no container on the node.
func TestPreparedNodeConfigPassesPluginStartup(t *testing.T) {
	pins, err := refvalues.Load("../../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(pins.Images) < 2 {
		t.Fatal("testdata needs two identities")
	}
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent, launchconfig.CDS} {
		t.Run(string(role), func(t *testing.T) {
			root := t.TempDir()
			write := func(name string, data []byte) {
				t.Helper()
				p := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("/usr/lib/c8s/image-policy.yaml", []byte(bakedNodeConfig))
			write("/usr/lib/c8s/allowlist-seed.json", []byte(bakedSeed))
			write("/usr/lib/c8s/cds-floor.json", []byte(bakedCDSFloor))
			for name, images := range map[string]int{"peers.json": len(pins.Images), "cds.json": 2} {
				p := pins
				p.Images = pins.Images[:images]
				data, err := refvalues.Format(p)
				if err != nil {
					t.Fatal(err)
				}
				write(launchconfig.Dir+"/"+name, data)
			}
			doc := &launchconfig.Document{
				Role:                  role,
				Image:                 launchconfig.Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}},
				Server:                launchconfig.ServerConfig{Address: "192.0.2.10", OperatorPublicKey: string(pins.Images[0].Anchor)},
				TLSSAN:                "c8s.local",
				ClusterID:             "cdsha",
				CDSOperatorPublicKeys: []string{string(pins.Images[1].Anchor)},
				CDSHA:                 &launchconfig.CDSHA{DecreeKey: string(pins.Images[1].Anchor), Replicas: 3, PinFloor: 5},
			}
			if err := nodeservices.Prepare(root, doc); err != nil {
				t.Fatal(err)
			}

			staged, err := os.ReadFile(filepath.Join(root, "etc/nri/conf.d/image-policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			// The plugin reads the launch directory at its absolute path on
			// the node; here it lives under root.
			launchPins := launchconfig.Dir + "/cds.json"
			if !bytes.Contains(staged, []byte(launchPins)) {
				t.Fatalf("staged config does not pin CDS by the launch policy %s:\n%s", launchPins, staged)
			}
			staged = bytes.ReplaceAll(staged, []byte(launchPins), []byte(filepath.Join(root, launchPins)))
			path := filepath.Join(t.TempDir(), "image-policy.yaml")
			if err := os.WriteFile(path, staged, 0o600); err != nil {
				t.Fatal(err)
			}
			runtimeDir := t.TempDir()
			if err := nriimagepolicy.CheckStartup(path, runtimeDir); err != nil {
				t.Fatalf("the plugin refuses the %s node's staged config: %v", role, err)
			}
			handed, err := os.ReadFile(filepath.Join(runtimeDir, "cds-pins.json"))
			if err != nil {
				t.Fatalf("no CDS pins handed to injected clients: %v", err)
			}
			got, err := refvalues.Parse(handed)
			if err != nil || len(got.Images) != 2 {
				t.Fatalf("handed CDS pins = %d images (%v), want the launch policy's server and cds key", len(got.Images), err)
			}
		})
	}
}
