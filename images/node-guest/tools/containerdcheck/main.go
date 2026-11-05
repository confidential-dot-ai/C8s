// Command containerdcheck proves that every ordinary-pod runtime handler of
// the worker image's containerd configuration reaches the measured runtime
// wrapper (c8s-runc), and not runc itself.
//
// The check reads the main config the image bakes and merges the drop-ins
// containerd imports, in the lexical order containerd merges them. It asserts
// against the effective configuration, so a drop-in that overrides a handler,
// an alternate runc or an empty BinaryName fails here rather than on a worker.
//
//	containerdcheck -wrapper /usr/local/bin/c8s-runc \
//	    -config-dir images/node-guest/worker/mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd \
//	    -config images/node-guest/worker/mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd/config.toml
package main

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

const (
	dropInDirName = "config-v3.toml.d"
	// criPlugin is the containerd v2 CRI runtime plugin: the one table the
	// ordinary-pod handlers live under.
	criPlugin = "io.containerd.cri.v1.runtime"
	runcShim  = "io.containerd.runc.v2"
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
	configDir := flags.String("config-dir", "", "containerd config directory holding "+dropInDirName)
	mainConfig := flags.String("config", "", "the containerd main config the image bakes")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *configDir == "" || *mainConfig == "" {
		fmt.Fprintln(stderr, "containerdcheck: -config-dir and -config are required")
		return 2
	}
	if !filepath.IsAbs(*wrapper) {
		fmt.Fprintf(stderr, "containerdcheck: -wrapper %q must be an absolute path\n", *wrapper)
		return 2
	}
	cfg, err := effectiveConfig(*configDir, *mainConfig)
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

// effectiveConfig reads mainConfig and merges configDir's drop-ins, returning
// what containerd would hold after loading the imports.
func effectiveConfig(
	configDir string,
	mainConfig string,
) (map[string]any, error) {
	data, err := os.ReadFile(mainConfig)
	if err != nil {
		return nil, err
	}
	cfg := map[string]any{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", mainConfig, err)
	}

	if err := checkImports(cfg); err != nil {
		return nil, err
	}

	dropIns, err := filepath.Glob(filepath.Join(configDir, dropInDirName, "*.toml"))
	if err != nil {
		return nil, err
	}
	slices.Sort(dropIns) // containerd merges imports in lexical order, later wins
	for _, path := range dropIns {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var imported map[string]any
		if err := toml.Unmarshal(data, &imported); err != nil {
			return nil, fmt.Errorf("parse drop-in %s: %w", path, err)
		}
		mergeTablesImportWins(cfg, imported)
	}
	return cfg, nil
}

// checkImports fails unless the config's one import is the drop-in directory
// this check merges. The wrapper's BinaryName lives in a drop-in, so a config
// that stopped importing them would silently fall back to PATH runc, and a
// second import would be a drop-in nothing here reads. The baked config names
// the directory by its absolute path on a worker, which is not where this
// check reads it from, so the import is matched by its last two elements.
func checkImports(cfg map[string]any) error {
	want := dropInDirName + "/*.toml"
	imports, _ := cfg["imports"].([]any)
	if len(imports) != 1 {
		return fmt.Errorf("the baked config imports %v, want only %q", imports, want)
	}
	if s, _ := imports[0].(string); !strings.HasSuffix(s, want) {
		return fmt.Errorf("the baked config imports %q, want %q, the drop-ins this check merges", s, want)
	}
	return nil
}

// mergeTablesImportWins merges an imported config over dst the way
// containerd's mergeConfig does: nested tables merge key by key, the import
// wins, and any other value, arrays included, is replaced whole.
func mergeTablesImportWins(dst, src map[string]any) {
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
		mergeTablesImportWins(existing, sub)
	}
}

// checkHandlers reports the ordinary-pod handlers, failing if any of them can
// reach a runtime other than wrapper. An unrecognised shim is a failure too:
// this gate's promise is that no handler the node enables escapes the wrapper,
// so a new one has to be classified deliberately.
func checkHandlers(cfg map[string]any, wrapper string) ([]string, error) {
	runtimes := table(cfg, "plugins", criPlugin, "containerd", "runtimes")
	if len(runtimes) == 0 {
		return nil, fmt.Errorf("no %s runtime handlers in the effective config", criPlugin)
	}

	var wrapped []string
	for _, name := range slices.Sorted(maps.Keys(runtimes)) {
		handler, ok := runtimes[name].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("runtime handler %q is not a table", name)
		}
		if shim, _ := handler["runtime_type"].(string); shim != runcShim {
			return nil, fmt.Errorf("runtime handler %q uses unaudited shim %q; only wrapped %s handlers may be enabled",
				name, shim, runcShim)
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

	// containerd runs "runc" when the config names no default handler.
	def, _ := table(cfg, "plugins", criPlugin, "containerd")["default_runtime_name"].(string)
	if def == "" {
		def = "runc"
	}
	if !slices.Contains(wrapped, def) {
		return nil, fmt.Errorf("default_runtime_name %q is not one of the wrapped handlers %v", def, wrapped)
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
