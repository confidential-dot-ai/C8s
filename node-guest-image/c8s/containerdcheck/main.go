// Command containerdcheck proves that every ordinary-pod runtime handler on
// the node image reaches the measured runtime wrapper (c8s-runc), and not runc
// itself.
//
// The check renders the containerd config the way RKE2 does — the vendored
// RKE2 base template, through the profile's config-v3.toml.tmpl if it bakes
// one — then merges the drop-ins containerd imports, in the lexical order
// containerd merges them. It asserts against the effective
// configuration, so a drop-in that overrides a handler, an alternate runc, an
// empty BinaryName or a runtime RKE2's auto-detection introduced all fail
// here rather than on a node.
//
//	containerdcheck -wrapper /usr/local/bin/c8s-runc \
//	    -config-dir node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd
//
// -extra-runtime NAME=BINARY adds a handler the way RKE2's runtime
// auto-detection would; the gate uses it to prove the check still fails when
// an unwrapped runtime appears on the node's PATH.
package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"text/template"

	toml "github.com/pelletier/go-toml/v2"
)

// The base template RKE2 renders, alone or as `{{ template "base" . }}` from
// a user template. Vendored: see the file's header for the pin and the
// re-vendor rule.
//
//go:embed rke2-base-v3.toml.tmpl
var baseTemplate string

const (
	userTemplateName = "config-v3.toml.tmpl"
	dropInDirName    = "config-v3.toml.d"
	// criPlugin is the containerd v2 CRI runtime plugin: the one table the
	// ordinary-pod handlers live under.
	criPlugin   = "io.containerd.cri.v1.runtime"
	runcShim    = "io.containerd.runc.v2"
	windowsShim = "io.containerd.runhcs.v1"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main with its inputs and outputs injected. It returns the process
// exit status: 0 when every handler is wrapped, 1 when the check fails, 2 on
// a usage error.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("containerdcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	wrapper := flags.String("wrapper", "/usr/local/bin/c8s-runc", "absolute path every ordinary-pod handler must run")
	configDir := flags.String("config-dir", "", "containerd config directory holding "+dropInDirName+" and, optionally, "+userTemplateName)
	var extra extraRuntimes
	flags.Var(&extra, "extra-runtime", "NAME=BINARY handler RKE2 auto-detection would add (repeatable; for negative tests)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configDir == "" {
		fmt.Fprintln(stderr, "containerdcheck: -config-dir is required")
		return 2
	}
	cfg, err := effectiveConfig(*configDir, extra)
	if err != nil {
		fmt.Fprintf(stderr, "containerdcheck: %v\n", err)
		return 1
	}
	handlers, err := checkHandlers(cfg, *wrapper)
	if err != nil {
		fmt.Fprintf(stderr, "::error::%v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "every ordinary-pod handler runs %s: %s\n", *wrapper, strings.Join(handlers, ", "))
	return 0
}

// extraRuntimes collects repeated -extra-runtime NAME=BINARY flags.
type extraRuntimes map[string]string

func (e extraRuntimes) String() string { return strings.Join(slices.Sorted(maps.Keys(e)), ",") }

func (e *extraRuntimes) Set(v string) error {
	name, binary, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("want NAME=BINARY, got %q", v)
	}
	if *e == nil {
		*e = extraRuntimes{}
	}
	(*e)[name] = binary
	return nil
}

// effectiveConfig renders the template in configDir and merges its drop-ins,
// returning what containerd would hold after loading the imports.
func effectiveConfig(configDir string, extra extraRuntimes) (map[string]any, error) {
	rendered, err := render(filepath.Join(configDir, userTemplateName), extra)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if err := toml.Unmarshal([]byte(rendered), &cfg); err != nil {
		return nil, fmt.Errorf("parse the rendered %s: %w\n%s", userTemplateName, err, rendered)
	}

	if err := checkImports(cfg); err != nil {
		return nil, err
	}

	dropIns, err := filepath.Glob(filepath.Join(configDir, dropInDirName, "*.toml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(dropIns) // containerd merges imports in lexical order, later wins
	for _, path := range dropIns {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var imported map[string]any
		if err := toml.Unmarshal(data, &imported); err != nil {
			return nil, fmt.Errorf("parse drop-in %s: %w", path, err)
		}
		mergeInto(cfg, imported)
	}
	return cfg, nil
}

// checkImports fails unless the rendered config imports the drop-in
// directory: the wrapper's BinaryName lives in a drop-in, so a base template
// that stopped importing them would silently fall back to PATH runc.
func checkImports(cfg map[string]any) error {
	want := dropInDirName + "/*.toml"
	imports, _ := cfg["imports"].([]any)
	for _, v := range imports {
		if s, ok := v.(string); ok && strings.HasSuffix(s, want) {
			return nil
		}
	}
	return fmt.Errorf("the rendered config has no import matching %q; the drop-in that wraps runc would never be read", want)
}

// render executes RKE2's base template with the node's rendering inputs,
// through the user template at path when one exists. RKE2 renders the base
// alone when the profile bakes none (k3s pkg/agent/containerd), and the C8s
// profile bakes none: the base already emits the drop-in import, and a user
// template that repeated it produced a duplicate key containerd refused.
func render(path string, extra extraRuntimes) (string, error) {
	user := `{{ template "base" . }}`
	if data, err := os.ReadFile(path); err == nil {
		user = string(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	funcs := template.FuncMap{
		// k3s's linux templateFuncs: deschemify is identity there, and no
		// containerd v3 template calls toJson.
		"deschemify":   func(s string) string { return s },
		"filepathjoin": filepath.Join,
	}
	t, err := template.New(userTemplateName).Funcs(funcs).Parse(user)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	if _, err := t.New("base").Parse(baseTemplate); err != nil {
		return "", fmt.Errorf("parse the vendored RKE2 base template: %w", err)
	}
	var out strings.Builder
	if err := t.Execute(&out, renderData(extra)); err != nil {
		return "", fmt.Errorf("render %s: %w", path, err)
	}
	return out.String(), nil
}

// renderData mirrors k3s's templates.ContainerdConfig for a C8s node: the
// fields the base template reads, with the values RKE2 fills in on this image.
// Only ExtraRuntimes varies, and only for the negative tests.
func renderData(extra extraRuntimes) map[string]any {
	runtimes := map[string]any{}
	for name, binary := range extra {
		runtimes[name] = map[string]any{"RuntimeType": runcShim, "BinaryName": binary}
	}
	return map[string]any{
		"Program":            "rke2",
		"SystemdCgroup":      true,
		"DisableCgroup":      false,
		"IsRunningInUserNS":  false,
		"EnableUnprivileged": true,
		"NonrootDevices":     false,
		"NoDefaultEndpoint":  false,
		"ExtraRuntimes":      runtimes,
		"PrivateRegistryConfig": map[string]any{
			"Configs": map[string]any{},
		},
		"NodeConfig": map[string]any{
			"SELinux":        false,
			"DefaultRuntime": "",
			"Containerd": map[string]any{
				"Root":          "/var/lib/rancher/rke2/agent/containerd",
				"State":         "/run/k3s/containerd",
				"Address":       "/run/k3s/containerd/containerd.sock",
				"Template":      "/var/lib/rancher/rke2/agent/etc/containerd",
				"Opt":           "/var/lib/rancher/rke2/agent/containerd",
				"Registry":      "/var/lib/rancher/rke2/agent/etc/containerd/certs.d",
				"BlockIOConfig": "",
				"RDTConfig":     "",
			},
			"AgentConfig": map[string]any{
				"Snapshotter":        "overlayfs",
				"PauseImage":         "index.docker.io/rancher/mirrored-pause:3.6",
				"CNIBinDir":          "/opt/cni/bin",
				"CNIConfDir":         "/etc/cni/net.d",
				"ImageServiceSocket": "",
			},
		},
	}
}

// mergeInto merges an imported config over dst the way containerd's
// mergeConfig does: nested tables merge key by key, and the import wins.
func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		sub, ok := v.(map[string]any)
		if !ok {
			dst[k] = v
			continue
		}
		existing, ok := dst[k].(map[string]any)
		if !ok {
			dst[k] = sub
			continue
		}
		mergeInto(existing, sub)
	}
}

// checkHandlers reports the ordinary-pod handlers, failing if any of them can
// reach a runtime other than wrapper. An unrecognised shim is a failure too:
// this gate's promise is that no handler the node enables escapes the wrapper,
// so a new one has to be classified deliberately.
func checkHandlers(cfg map[string]any, wrapper string) ([]string, error) {
	if !filepath.IsAbs(wrapper) {
		return nil, fmt.Errorf("-wrapper %q must be an absolute path", wrapper)
	}
	runtimes := table(cfg, "plugins", criPlugin, "containerd", "runtimes")
	if len(runtimes) == 0 {
		return nil, fmt.Errorf("no %s runtime handlers in the effective config; the template did not render the CRI plugin", criPlugin)
	}

	var wrapped []string
	for _, name := range slices.Sorted(maps.Keys(runtimes)) {
		handler, ok := runtimes[name].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("runtime handler %q is not a table", name)
		}
		shim, _ := handler["runtime_type"].(string)
		switch shim {
		case runcShim:
		case windowsShim:
			// Windows-only shim the base template always emits; it has no
			// binary on a Linux node, so a pod selecting it never starts.
			continue
		default:
			return nil, fmt.Errorf("runtime handler %q uses unaudited shim %q; only %s (wrapped) and %s handlers may be enabled",
				name, shim, runcShim, windowsShim)
		}
		binary, _ := table(handler, "options")["BinaryName"].(string)
		if binary != wrapper {
			return nil, fmt.Errorf("runtime handler %q runs BinaryName %q, want the measured wrapper %q (an empty BinaryName resolves runc through PATH)",
				name, binary, wrapper)
		}
		wrapped = append(wrapped, name)
	}
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("no %s handler is enabled; ordinary pods would have no runtime", runcShim)
	}

	if def, ok := table(cfg, "plugins", criPlugin, "containerd")["default_runtime_name"].(string); ok && def != "" {
		if !slices.Contains(wrapped, def) {
			return nil, fmt.Errorf("default_runtime_name %q is not one of the wrapped handlers %v", def, wrapped)
		}
	}
	return wrapped, nil
}

// table walks nested TOML tables, returning an empty map at the first missing
// or non-table step.
func table(m map[string]any, path ...string) map[string]any {
	for _, key := range path {
		next, ok := m[key].(map[string]any)
		if !ok {
			return map[string]any{}
		}
		m = next
	}
	return m
}
