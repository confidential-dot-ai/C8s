package helmchart

import (
	"reflect"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
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
