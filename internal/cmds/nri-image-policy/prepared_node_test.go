package nriimagepolicy_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/adaptation"

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
	for _, role := range []launchconfig.Role{launchconfig.Server, launchconfig.Agent, launchconfig.CDS} {
		t.Run(string(role), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image-policy.yaml")
			if err := os.WriteFile(path, preparedNodeConfig(t, role), 0o600); err != nil {
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

// preparedNodeConfig is the plugin config nodeservices.Prepare stages for a
// node of role in an HA cluster, with the launch policy it names rebased
// into a temporary root.
func preparedNodeConfig(t *testing.T, role launchconfig.Role) []byte {
	t.Helper()
	pins, err := refvalues.Load("../../../internal/testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(pins.Images) < 2 {
		t.Fatal("testdata needs two identities")
	}
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
		Server:                launchconfig.ServerConfig{Address: preparedServerAddress, OperatorPublicKey: string(pins.Images[0].Anchor)},
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
	// The plugin reads the launch directory at its absolute path on the
	// node; here it lives under root.
	launchPins := launchconfig.Dir + "/cds.json"
	if !bytes.Contains(staged, []byte(launchPins)) {
		t.Fatalf("staged config does not pin CDS by the launch policy %s:\n%s", launchPins, staged)
	}
	return bytes.ReplaceAll(staged, []byte(launchPins), []byte(filepath.Join(root, launchPins)))
}

const preparedServerAddress = "192.0.2.10"

// TestPreparedAgentRegistersWhileCDSHangs runs the plugin in a process of its
// own, started with these set.
const (
	pluginConfigEnv     = "C8S_TEST_NRI_PLUGIN_CONFIG"
	pluginRuntimeDirEnv = "C8S_TEST_NRI_PLUGIN_RUNTIME_DIR"
)

// An agent can boot while its server's CDS port has no ready replica behind
// it (a new HA cluster before Genesis), where packets to the port are
// dropped. containerd kills a plugin that has not registered within its
// registration timeout and never starts it again, and its default validator,
// which requires the plugin, then refuses every container on the node. So
// the plugin registers with NRI while its CDS fetches still hang.
func TestPreparedAgentRegistersWhileCDSHangs(t *testing.T) {
	if config := os.Getenv(pluginConfigEnv); config != "" {
		err := nriimagepolicy.RunIn(os.Getenv(pluginRuntimeDirEnv), []string{"-config", config, "-health-addr", "127.0.0.1:0"})
		t.Fatalf("plugin exited: %v", err)
	}
	cds, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := cds.Accept()
			if err != nil {
				close(held)
				return
			}
			held <- conn // never answered
		}
	}()
	defer func() {
		cds.Close()
		for conn := range held {
			conn.Close()
		}
	}()

	// Unix socket paths must stay short.
	dir, err := os.MkdirTemp("", "nri")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	staged := preparedNodeConfig(t, launchconfig.Agent)
	for from, to := range map[string]string{
		"https://" + preparedServerAddress + ":30808": "https://" + cds.Addr().String(),
		"/run/nri-image-policy/":                      dir + "/",
	} {
		if !bytes.Contains(staged, []byte(from)) {
			t.Fatalf("staged agent config names no %s:\n%s", from, staged)
		}
		staged = bytes.ReplaceAll(staged, []byte(from), []byte(to))
	}
	if !bytes.Contains(staged, []byte("cds_decrees:")) {
		t.Fatalf("staged agent config follows no CDS pin decrees:\n%s", staged)
	}
	// The admission inventory hands its socket to a group only root can
	// assign; it plays no part in registration.
	inventory := []byte("socket_dir: /run/c8s-enforcer-inventory\n")
	if !bytes.Contains(staged, inventory) {
		t.Fatalf("staged agent config names no inventory:\n%s", staged)
	}
	staged = bytes.ReplaceAll(staged, inventory, nil)
	config := filepath.Join(dir, "image-policy.yaml")
	if err := os.WriteFile(config, staged, 0o600); err != nil {
		t.Fatal(err)
	}

	registered := make(chan struct{}, 1)
	nri, err := adaptation.New("containerd", "test",
		func(ctx context.Context, sync adaptation.SyncCB) error {
			if _, err := sync(ctx, nil, nil); err != nil {
				return err
			}
			registered <- struct{}{}
			return nil
		},
		func(context.Context, []*adaptation.ContainerUpdate) ([]*adaptation.ContainerUpdate, error) {
			return nil, nil
		},
		adaptation.WithSocketPath(filepath.Join(dir, "nri.sock")),
		adaptation.WithPluginPath(filepath.Join(dir, "plugins")),
		adaptation.WithPluginConfigPath(filepath.Join(dir, "conf.d")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := nri.Start(); err != nil {
		t.Fatal(err)
	}
	// Start synchronizes the plugins it launched itself, of which there are none.
	select {
	case <-registered:
	default:
	}
	defer nri.Stop()
	// The plugin runs as containerd starts it: its own process, connected
	// over an inherited socket.
	conn, err := net.Dial("unix", filepath.Join(dir, "nri.sock"))
	if err != nil {
		t.Fatal(err)
	}
	socket, err := conn.(*net.UnixConn).File()
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	plugin := exec.Command(os.Args[0], "-test.run=^TestPreparedAgentRegistersWhileCDSHangs$")
	plugin.Env = append(os.Environ(), "NRI_PLUGIN_NAME=image-policy", "NRI_PLUGIN_IDX=00", "NRI_PLUGIN_SOCKET=3",
		pluginConfigEnv+"="+config, pluginRuntimeDirEnv+"="+filepath.Join(dir, "enforcer"))
	plugin.ExtraFiles = []*os.File{socket}
	plugin.Stdout, plugin.Stderr = os.Stderr, os.Stderr
	if err := plugin.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- plugin.Wait() }()
	defer func() {
		_ = plugin.Process.Kill()
		<-exited
	}()
	select {
	case <-registered:
	case err := <-exited:
		t.Fatalf("the plugin exited before it registered: %v", err)
	case <-time.After(adaptation.DefaultPluginRegistrationTimeout + time.Second):
		t.Fatalf("the plugin did not register within NRI's registration timeout (%v) while CDS hangs", adaptation.DefaultPluginRegistrationTimeout)
	}
}
