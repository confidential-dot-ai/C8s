package launchconfig

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

func podTrustPolicy(t *testing.T, key string) string {
	t.Helper()
	data, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilyTDX,
		Images: []remote.ImagePin{{Name: "pod", Digest: bytes.Repeat([]byte{0x44}, 48),
			Registers: map[int][]byte{1: bytes.Repeat([]byte{0x55}, 48), 2: bytes.Repeat([]byte{0x66}, 48)},
			Anchor:    []byte(key)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPodPolicyCannotGrantNodeAuthority(t *testing.T) {
	doc, _, _ := testDocument(t, "tdx", Server)
	_, podKey := testKey(t)
	for _, tc := range []struct {
		name string
		key  string
		want string
	}{
		{"pod", podKey, ""},
		{"server", doc.Server.OperatorPublicKey, "must differ"},
		{"agent", doc.AgentOperatorPublicKeys[0], "must differ"},
		{"server alternate PEM whitespace", doc.Server.OperatorPublicKey + "\n", "must differ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := doc
			d.PodImagePolicy = podTrustPolicy(t, tc.key)
			err := d.validate()
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("wanted %q, got %v", tc.want, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			pins, err := d.referenceValues()
			if err != nil {
				t.Fatal(err)
			}
			for _, pin := range pins.Images {
				if bytes.Equal(pin.Anchor, []byte(podKey)) {
					t.Fatal("Pod key became a node peer")
				}
			}
		})
	}
	for _, role := range []Role{Agent, Pod} {
		d, _, _ := testDocument(t, "tdx", role)
		if role == Pod {
			d, _, _ = testPodDocument(t, "tdx")
		}
		d.PodImagePolicy = podTrustPolicy(t, podKey)
		if err := d.validate(); err == nil || !strings.Contains(err.Error(), "server-only") {
			t.Fatalf("%s accepted Pod trust policy: %v", role, err)
		}
	}
}

func TestPodPolicyStageClearsTrustOnRoleChangeAndFailure(t *testing.T) {
	doc, key, pub := testDocument(t, "tdx", Server)
	_, podKey := testKey(t)
	doc.PodImagePolicy = podTrustPolicy(t, podKey)
	testLoader(t, doc, pub)
	cfg := testConfig(t, doc, key)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(cfg.path(Dir + "/pods.json"))
	if err != nil || string(got) != doc.PodImagePolicy {
		t.Fatalf("staged Pod policy: %v", err)
	}
	agent, agentKey, agentPub := testDocument(t, "tdx", Agent)
	testLoader(t, agent, agentPub)
	signDocument(t, cfg, agent, agentKey)
	if err := Stage(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.path(Dir + "/pods.json")); !os.IsNotExist(err) {
		t.Fatalf("agent retained Pod trust: %v", err)
	}
	if err := os.WriteFile(cfg.path(Dir+"/pods.json"), got, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SignaturePath, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Stage(context.Background(), cfg); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, err := os.Stat(cfg.path(Dir + "/pods.json")); !os.IsNotExist(err) {
		t.Fatalf("failed launch retained Pod trust: %v", err)
	}
}

func TestBundlePodPolicyRemainsServerOnly(t *testing.T) {
	_, podKey := testKey(t)
	policy := podTrustPolicy(t, podKey)
	path := filepath.Join(t.TempDir(), "pods.json")
	if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := runBundleCmd(t, "new", "--out", dir, "--cluster-id", "pod-trust",
		"--image-manifest", writeManifest(t, "tdx"), "--server-address", "192.0.2.10",
		"--agent", "worker", "--pod-image-policy-file", path); err != nil {
		t.Fatal(err)
	}
	server, _ := readBundleDocument(t, dir, serverDir)
	agent, _ := readBundleDocument(t, dir, "worker")
	if server.PodImagePolicy != policy || agent.PodImagePolicy != "" {
		t.Fatal("bundle did not keep Pod authorization server-only")
	}
	stageBundleNode(t, dir, serverDir)
	stageBundleNode(t, dir, "worker")
}
