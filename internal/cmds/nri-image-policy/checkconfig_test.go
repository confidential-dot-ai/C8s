package nriimagepolicy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCDSPin names pin as the CDS pin file of a boot config document.
func withCDSPin(document, pin string) string {
	return strings.Replace(document, "  pull:\n", "  pull:\n    cds_measurements_config: "+pin+"\n", 1)
}

// withSyslog has a boot config document log to a socket that is listened on.
func withSyslog(t *testing.T, document string) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "log")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return document + "logging:\n  syslog: " + socket + "\n"
}

// The installer runs this verb on the boot config it is about to hand
// containerd, and refuses the install when it fails.
func TestRunCheckConfig(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
	}{
		{
			"a config the plugin starts with",
			withSyslog(t, withCDSPin(bootConfigDocument("[kube-system]", "[kube-system]"), testCDSPinFile(t))),
			"",
		},
		{
			"an exemption the mesh does not exempt",
			withSyslog(t, withCDSPin(bootConfigDocument("[gmp-system]", "[kube-system]"), testCDSPinFile(t))),
			"must also be in mesh.exempt_namespaces",
		},
		{
			"a CDS pin file that pins no image",
			withSyslog(t, withCDSPin(bootConfigDocument("[kube-system]", "[kube-system]"), cdsPinFile(t, `{"schema_version":"1","tee":"sev-snp"}`))),
			"allowlist.pull",
		},
		{
			"a syslog socket nothing listens on",
			withCDSPin(bootConfigDocument("[kube-system]", "[kube-system]"), testCDSPinFile(t)) + "logging:\n  syslog: " + filepath.Join(t.TempDir(), "log") + "\n",
			"logging.syslog",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "image-policy.yaml")
			if err := os.WriteFile(path, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}
			err := Run([]string{checkConfigVerb, "--config=" + path})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("check-config = %v, want the config accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("check-config = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}

	t.Run("a missing file", func(t *testing.T) {
		if err := Run([]string{checkConfigVerb, "--config=" + filepath.Join(t.TempDir(), "absent.yaml")}); err == nil {
			t.Fatal("check-config accepted a config file that does not exist")
		}
	})
}

// requiringDump is containerd's effective NRI config as the installer writes
// it, in the key quoting of config version 3.
const requiringDump = `version = 3

[plugins.'io.containerd.nri.v1.nri']
  disable = false
  plugin_path = '/opt/nri/plugins'

  [plugins.'io.containerd.nri.v1.nri'.default_validator]
    enable = true
    required_plugins = ['nri-image-policy']
`

// The installer pipes containerd's config dump through this verb on every
// run: an import or a containerd without the validator would start
// containers the plugin never saw.
func TestRunCheckContainerdConfig(t *testing.T) {
	for _, tc := range []struct {
		name, dump, want string
	}{
		{"the gate in place", requiringDump, ""},
		{"no NRI table", "version = 2\n", "no io.containerd.nri.v1.nri plugin config"},
		{"NRI disabled", strings.Replace(requiringDump, "disable = false", "disable = true", 1), "NRI is disabled"},
		{"another plugin dir", strings.Replace(requiringDump, "/opt/nri/plugins", "/home/kubernetes/bin/nri", 1), "launches NRI plugins from"},
		{"the validator off", strings.Replace(requiringDump, "enable = true", "enable = false", 1), "default_validator is not enabled"},
		{"a containerd without the validator", strings.Split(requiringDump, "\n  [plugins")[0], "default_validator is not enabled"},
		{"another plugin required", strings.Replace(requiringDump, "['nri-image-policy']", "['other']", 1), "requires [other]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runCheckContainerdConfig([]string{"--plugin-dir=/opt/nri/plugins", "--required-plugin=nri-image-policy"}, strings.NewReader(tc.dump))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("check-containerd-config = %v, want the config accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("check-containerd-config = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}
