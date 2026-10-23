package helmchart

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// nriPlugin is containerd's NRI plugin id: the one table its NRI
// configuration, built-in validator included, lives under.
const nriPlugin = "io.containerd.nri.v1.nri"

// The installer writes the NRI configuration containerd loads from
// render_nri_toml. containerd nests the built-in validator as
// default_validator under the NRI plugin's own table; a table opened under
// one quoted key is a plugin id of its own, which containerd never reads, so
// the validator stayed disabled and required_plugins empty.
func TestChartNriInstallerEnablesRequiredPluginGate(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	args := containerArgs(t, &worker, "install")
	if len(args) != 1 {
		t.Fatalf("install init container args = %d entries, want the script alone", len(args))
	}
	cfg := map[string]any{}
	if err := toml.Unmarshal([]byte(renderedNriToml(t, args[0])), &cfg); err != nil {
		t.Fatalf("render_nri_toml output is not TOML: %v", err)
	}
	plugins, _ := cfg["plugins"].(map[string]any)
	if _, stray := plugins[nriPlugin+".default_validator"]; stray {
		t.Errorf("render_nri_toml opens %q as a plugin of its own; containerd reads the validator from %s.default_validator", nriPlugin+".default_validator", nriPlugin)
	}
	nri, _ := plugins[nriPlugin].(map[string]any)
	validator, ok := nri["default_validator"].(map[string]any)
	if !ok {
		t.Fatalf("no default_validator table under plugins.%q; have %v", nriPlugin, nri)
	}
	if enable, _ := validator["enable"].(bool); !enable {
		t.Errorf("default_validator.enable = %v, want true", validator["enable"])
	}
	if got, want := validator["required_plugins"], []any{"nri-image-policy"}; !reflect.DeepEqual(got, want) {
		t.Errorf("default_validator.required_plugins = %v, want %v", got, want)
	}
}

// renderedNriToml returns the heredoc render_nri_toml prints in script.
func renderedNriToml(t *testing.T, script string) string {
	t.Helper()
	const open = "render_nri_toml() {\n  cat <<EOF\n"
	_, rest, ok := strings.Cut(script, open)
	if !ok {
		t.Fatalf("install script has no %q", strings.TrimSpace(open))
	}
	body, _, ok := strings.Cut(rest, "\nEOF\n")
	if !ok {
		t.Fatal("render_nri_toml heredoc is unterminated")
	}
	return body
}

// plugin_request_timeout is how long containerd waits on one callback before
// NRI drops the plugin, so it is the operator's lever against a callback that
// overruns on a busy node (#683). The schema keeps it a duration: it lands
// unescaped in a shell heredoc and in containerd's TOML.
func TestChartNriInstallerRequestTimeout(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "2s"},
		{"override", []string{"--set-string", "nriImagePolicy.requestTimeout=1m30s"}, "1m30s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
			cfg := map[string]any{}
			if err := toml.Unmarshal([]byte(renderedNriToml(t, containerArgs(t, &worker, "install")[0])), &cfg); err != nil {
				t.Fatalf("render_nri_toml output is not TOML: %v", err)
			}
			plugins, _ := cfg["plugins"].(map[string]any)
			nri, _ := plugins[nriPlugin].(map[string]any)
			if got := nri["plugin_request_timeout"]; got != tc.want {
				t.Errorf("plugin_request_timeout = %v, want %q", got, tc.want)
			}
		})
	}

	for _, bad := range []string{"2", "2 s", `2s"; reboot; "`, "-1s"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			if out, err := helmTemplate(t, "--set-string", "nriImagePolicy.requestTimeout="+bad); err == nil {
				t.Fatalf("helm template accepted requestTimeout %q\n%s", bad, out)
			}
		})
	}
}

// The installer's long-running container is the only Kubernetes-visible
// stand-in for the host plugin, which NRI does not respawn once it exits
// (#683). Its readiness has to follow that process, not a sleep.
func TestChartNriInstallerReadinessTracksPluginProcess(t *testing.T) {
	t.Parallel()
	const pluginDir = "/opt/nri/test-plugins"
	// /bin/sh -c like the entry's other scripts: released `c8s uninstall`
	// CLIs take the one non-script shape there as the sweep pause.
	wantArgv := []string{"/bin/sh", "-c",
		"exec /usr/local/bin/c8s nri-image-policy plugin-ready --plugin-path='" + pluginDir + "/10-nri-image-policy' --addr=:8080",
	}
	for _, baked := range []bool{false, true} {
		t.Run(fmt.Sprintf("baked=%v", baked), func(t *testing.T) {
			out, err := helmTemplate(t,
				"--set", "nriImagePolicy.baked="+strconv.FormatBool(baked),
				"--set", "nriImagePolicy.hostPaths.pluginDir="+pluginDir)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			worker := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
			if !worker.Spec.Template.Spec.HostPID {
				t.Fatal("installer pod is not hostPID; the endpoint cannot see the host plugin")
			}
			c := renderedDaemonSetContainer(t, out, "c8s-nri-image-policy-worker", "plugin-ready")
			if got := append(append([]string{}, c.Command...), c.Args...); !reflect.DeepEqual(got, wantArgv) {
				t.Errorf("plugin-ready argv = %q, want %q", got, wantArgv)
			}
			// A liveness restart reruns neither the install nor containerd, so
			// it cannot bring the plugin back.
			if c.LivenessProbe != nil {
				t.Errorf("plugin-ready has a liveness probe %+v; restarting it does not recover the plugin", c.LivenessProbe)
			}
			// HTTP, not exec: the locked node image denies runc exec.
			probe := c.ReadinessProbe
			if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Path != "/readyz" {
				t.Fatalf("plugin-ready readiness probe = %+v, want httpGet /readyz", probe)
			}
			if len(c.Ports) != 1 || c.Ports[0].ContainerPort != 8080 || probe.HTTPGet.Port.String() != c.Ports[0].Name {
				t.Errorf("readiness probe port %v does not name the endpoint's port %+v", probe.HTTPGet.Port.String(), c.Ports)
			}

			// The seed admits exactly this invocation, and only without a host
			// mount: the container carries none.
			if len(c.VolumeMounts) != 0 {
				t.Errorf("plugin-ready mounts %v; its argv-pinned seed entry denies mounts", c.VolumeMounts)
			}
			cm := renderedConfigMap(t, out, "c8s-cds-allowlist-seed")
			seed, err := pkgallowlist.ParseJSON([]byte(cm.Data["allowlist-seed.json"]))
			if err != nil {
				t.Fatal(err)
			}
			idx := seed.BuildIndex()
			hostMount := []pkgallowlist.ObservedMount{{Source: "/", Destination: "/host", Class: pkgallowlist.MountHost, Storage: pkgallowlist.MountUnknown}}
			for _, tc := range []struct {
				name   string
				argv   []string
				mounts []pkgallowlist.ObservedMount
				want   bool
			}{
				{"rendered", wantArgv, []pkgallowlist.ObservedMount{}, true},
				{"with host mount", wantArgv, hostMount, false},
				{"other script", []string{"/bin/sh", "-c", wantArgv[2] + "; sh"}, []pkgallowlist.ObservedMount{}, false},
			} {
				if got := idx.AdmitsContainer(pkgallowlist.RunningContainer{Digest: baseNRIDigest, Argv: tc.argv, Mounts: tc.mounts}); got != tc.want {
					t.Errorf("seed admits %s = %v, want %v", tc.name, got, tc.want)
				}
			}
		})
	}
}

// The plugin path lands single-quoted in the plugin-ready and install sh -c
// scripts, so the schema keeps quotes and shell syntax out of it.
func TestChartNriInstallerRejectsShellInPluginPath(t *testing.T) {
	t.Parallel()
	for _, set := range []string{
		"nriImagePolicy.hostPaths.pluginDir=/opt/nri/plug'ins",
		"nriImagePolicy.hostPaths.pluginDir=opt/nri/plugins",
		"nriImagePolicy.hostPaths.pluginDir=/opt/$(reboot)",
		"nriImagePolicy.pluginFilename=10-nri;reboot",
		"nriImagePolicy.pluginFilename=sub/10-nri",
	} {
		t.Run(set, func(t *testing.T) {
			if out, err := helmTemplate(t, "--set-string", set); err == nil {
				t.Fatalf("helm template accepted %s\n%s", set, out)
			}
		})
	}
}
