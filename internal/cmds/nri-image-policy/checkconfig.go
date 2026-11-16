package nriimagepolicy

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	toml "github.com/pelletier/go-toml/v2"
)

// checkConfigVerb selects a check of a config file in place of the plugin
// daemon: the installer runs it before it hands containerd a config.
const checkConfigVerb = "check-config"

// checkContainerdConfigVerb selects a check of containerd's effective config,
// as `containerd config dump` prints it, in place of the plugin daemon.
const checkContainerdConfigVerb = "check-containerd-config"

// NRIPluginID is containerd's NRI plugin, whose table holds the validator.
const NRIPluginID = "io.containerd.nri.v1.nri"

// runCheckConfig loads --config and opens the files and socket it names as the
// plugin does at start, and returns the error the plugin would exit with.
func runCheckConfig(args []string) error {
	fs := flag.NewFlagSet("nri-image-policy "+checkConfigVerb, flag.ContinueOnError)
	configPath := fs.String("config", DefaultConfigPath, "path to the config file to check")
	if err := parseOnlyFlags(fs, args); err != nil {
		return err
	}
	data, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	cfg, err := checkedConfig(data)
	if err != nil {
		return fmt.Errorf("config %q: %w", *configPath, err)
	}
	if err := openStartInputs(cfg); err != nil {
		return fmt.Errorf("config %q: %w", *configPath, err)
	}
	return nil
}

// openStartInputs opens what the plugin opens at start beyond its config: its
// log sink and the CDS identity set its clients are held to.
func openStartInputs(cfg *config) error {
	logOut, err := logWriter(cfg.Logging)
	if err != nil {
		return err
	}
	defer func() { _ = logOut.Close() }()
	if !cfg.PullEnabled() {
		return nil
	}
	_, err = cfg.Allowlist.Pull.policySet()
	return err
}

// runCheckContainerdConfig reads containerd's effective config from stdin and
// refuses one that lets a container start without the plugin.
func runCheckContainerdConfig(args []string, stdin io.Reader) error {
	fs := flag.NewFlagSet("nri-image-policy "+checkContainerdConfigVerb, flag.ContinueOnError)
	pluginDir := fs.String("plugin-dir", "", "directory containerd must launch NRI plugins from")
	plugin := fs.String("required-plugin", "", "plugin name containerd's NRI validator must require")
	if err := parseOnlyFlags(fs, args); err != nil {
		return err
	}
	if *pluginDir == "" || *plugin == "" {
		return fmt.Errorf("--plugin-dir and --required-plugin are required")
	}
	dump, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read containerd config: %w", err)
	}
	return checkNRIRequiresPlugin(dump, *pluginDir, *plugin)
}

// ContainerdNRIConfig is the part of a containerd config that gates every
// container on the plugin, as containerd's own config and its effective dump
// carry it.
type ContainerdNRIConfig struct {
	Plugins map[string]struct {
		Disable          bool   `toml:"disable"`
		PluginPath       string `toml:"plugin_path"`
		DefaultValidator struct {
			Enable          bool     `toml:"enable"`
			RequiredPlugins []string `toml:"required_plugins"`
		} `toml:"default_validator"`
	} `toml:"plugins"`
}

// checkNRIRequiresPlugin names the first setting of dump under which
// containerd starts a container the plugin has not admitted.
func checkNRIRequiresPlugin(dump []byte, pluginDir, plugin string) error {
	var cfg ContainerdNRIConfig
	if err := toml.Unmarshal(dump, &cfg); err != nil {
		return fmt.Errorf("parse containerd config: %w", err)
	}
	nri, ok := cfg.Plugins[NRIPluginID]
	switch {
	case !ok:
		return fmt.Errorf("containerd has no %s plugin config", NRIPluginID)
	case nri.Disable:
		return fmt.Errorf("containerd's NRI is disabled")
	case filepath.Clean(nri.PluginPath) != filepath.Clean(pluginDir):
		return fmt.Errorf("containerd launches NRI plugins from %q, not %q", nri.PluginPath, pluginDir)
	case !nri.DefaultValidator.Enable:
		return fmt.Errorf("containerd's NRI default_validator is not enabled (an imported drop-in, or a containerd without the validator)")
	case !slices.Contains(nri.DefaultValidator.RequiredPlugins, plugin):
		return fmt.Errorf("containerd's NRI default_validator requires %v, not %q", nri.DefaultValidator.RequiredPlugins, plugin)
	}
	return nil
}
