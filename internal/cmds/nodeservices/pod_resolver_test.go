package nodeservices

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPodResolvConfNamesOnlyMeasuredRemoteResolvers(t *testing.T) {
	for _, tt := range []struct {
		name  string
		files map[string]string
		want  string
		fail  string
	}{
		{
			name:  "upstreams with resolved's name and interface suffixes, deduplicated across drop-ins",
			files: map[string]string{"10-upstream.conf": "[Resolve]\nDNS=1.1.1.1 8.8.8.8#dns.google\nDomains=~.\n", "20-more.conf": "DNS = 9.9.9.9%eth0 1.1.1.1\n", "README": "DNS=203.0.113.1\n"},
			want:  "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\n",
		},
		{name: "no resolver", files: map[string]string{"10-upstream.conf": "[Resolve]\nDomains=~.\n"}, fail: "no upstream resolver"},
		{name: "loopback stub", files: map[string]string{"10-upstream.conf": "DNS=127.0.0.53\n"}, fail: "not a remote unicast IPv4"},
		{name: "link-local", files: map[string]string{"10-upstream.conf": "DNS=169.254.169.254\n"}, fail: "not a remote unicast IPv4"},
		{name: "the guest's own link", files: map[string]string{"10-upstream.conf": "DNS=10.255.254.1\n"}, fail: "not a remote unicast IPv4"},
		{name: "IPv6", files: map[string]string{"10-upstream.conf": "DNS=2606:4700:4700::1111\n"}, fail: "not a remote unicast IPv4"},
		{name: "unparsable", files: map[string]string{"10-upstream.conf": "DNS=dns.example\n"}, fail: "measured resolver"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, bakedResolvedConfDir)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, data := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := podResolvConf(root)
			if tt.fail != "" {
				if err == nil || !strings.Contains(err.Error(), tt.fail) {
					t.Fatalf("got %q, %v; want an error containing %q", got, err, tt.fail)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	if _, err := podResolvConf(t.TempDir()); err == nil {
		t.Fatal("a missing drop-in directory was accepted")
	}
}

func TestPreparePodStagesTheMeasuredResolverFile(t *testing.T) {
	root := preparePodRoot(t)
	if err := preparePodFixture(root, podDocument(t)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, podResolvConfPath))
	if err != nil {
		t.Fatal(err)
	}
	baked, err := os.ReadFile("../../../images/node-guest/c8s/mkosi.extra" + bakedResolvedConfDir + "/10-upstream.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		addr, ok := strings.CutPrefix(line, "nameserver ")
		if !ok || !strings.Contains(string(baked), addr) {
			t.Fatalf("resolver file line %q is not a measured upstream", line)
		}
	}
	if !strings.Contains(string(data), "nameserver ") {
		t.Fatalf("resolver file %q names no resolver", data)
	}
}
