package getcert

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSANFile(t *testing.T) {
	for _, want := range []string{"c8s.example.com", "192.0.2.1", "2001:db8::1"} {
		path := filepath.Join(t.TempDir(), "tls-san")
		if err := os.WriteFile(path, []byte(want+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := resolveSAN(config{SANFile: path})
		if err != nil || got != want {
			t.Fatalf("SAN = %q, %v; want %q", got, err, want)
		}
		if _, err := resolveSAN(config{
			SAN:     "override.example",
			SANFile: path,
		}); err == nil {
			t.Fatal("accepted an override of the staged SAN")
		}
	}
}

func TestSANFileFailsBeforeNetworkOrOutputs(t *testing.T) {
	for _, value := range []string{"", "\n", "*.example.com", "https://example.com", "first.example\nsecond.example", strings.Repeat("x", 1025)} {
		t.Run(value, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tls-san")
			if err := os.WriteFile(path, []byte(value), 0644); err != nil {
				t.Fatal(err)
			}
			err := run(config{
				SANFile:  path,
				CDSURL:   "invalid",
				CertPath: filepath.Join(root, "out", "cert.pem"),
			})
			if err == nil || strings.Contains(err.Error(), "cds-url") {
				t.Fatalf("did not reject SAN before client setup: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "out")); !os.IsNotExist(err) {
				t.Fatal("invalid SAN created output directory")
			}
		})
	}
	if _, err := resolveSAN(config{SANFile: filepath.Join(t.TempDir(), "missing")}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing SAN file: %v", err)
	}
}

// The SAN has exactly one source, and "no SAN" is one of them — a pod with
// no SAN flag at all is a misconfiguration, not a SANless pod.
func TestSANFlagsRequireExactlyOneSource(t *testing.T) {
	for _, args := range [][]string{nil, {"--san=x", "--san-file=/staged"}, {"--san=x", "--no-san"}, {"--san=x"}, {"--san-file=/staged"}, {"--no-san"}} {
		cmd := NewCmd()
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		err := cmd.ValidateFlagGroups()
		if (err == nil) != (len(args) == 1) {
			t.Fatalf("args %v: %v", args, err)
		}
	}
	san, err := resolveSAN(config{NoSAN: true})
	if san != "" || err != nil {
		t.Fatalf("resolveSAN with --no-san = %q, %v; want no SAN", san, err)
	}
	if _, err := resolveSAN(config{}); err == nil {
		t.Fatal("accepted a pod with no SAN source at all")
	}
	if _, err := resolveSAN(config{
		NoSAN: true,
		SAN:   "host.example.com",
	}); err == nil {
		t.Fatal("accepted --no-san beside --san")
	}
}
