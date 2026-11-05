package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wrapper = "/usr/local/bin/c8s-runc"

// bakedConfigDir is the worker profile's containerd directory, the one the CI
// gate checks.
const bakedConfigDir = "../../worker/mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd"

// bakedConfig is the worker image's baked main config, beside its drop-ins.
const bakedConfig = bakedConfigDir + "/config.toml"

// The worker image as committed must pass: its baked config and drop-ins; a
// handler it adds unwrapped fails.
func TestWorkerConfigWrapsEveryHandler(t *testing.T) {
	cfg, err := effectiveConfig(bakedConfigDir, bakedConfig)
	if err != nil {
		t.Fatalf("effectiveConfig(worker) = %v", err)
	}
	if handlers, err := checkHandlers(cfg, wrapper); err != nil || len(handlers) != 1 || handlers[0] != "runc" {
		t.Fatalf("checkHandlers(worker) = %v, %v; want the runc handler wrapped", handlers, err)
	}
	data, err := os.ReadFile(bakedConfig)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped := filepath.Join(t.TempDir(), "config.toml")
	extra := "\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.crun]\n  runtime_type = \"io.containerd.runc.v2\"\n"
	if err := os.WriteFile(unwrapped, append(data, extra...), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = effectiveConfig(bakedConfigDir, unwrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkHandlers(cfg, wrapper); err == nil || !strings.Contains(err.Error(), "crun") {
		t.Fatalf("checkHandlers(worker + crun) = %v, want the unwrapped crun handler refused", err)
	}
}

// buildConfigDir is a containerd directory holding the drop-ins and a main
// config shaped like the image's: the runc handler and the drop-in import.
func buildConfigDir(t *testing.T, dropIns map[string]string) (dir, mainConfig string) {
	t.Helper()
	dir = t.TempDir()
	dropInDir := filepath.Join(dir, dropInDirName)
	if err := os.MkdirAll(dropInDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range dropIns {
		if err := os.WriteFile(filepath.Join(dropInDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mainConfig = filepath.Join(dir, "config.toml")
	body := "version = 3\nimports = [\"" + filepath.Join(dir, dropInDirName, "*.toml") + "\"]\n" +
		"[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\n  runtime_type = \"" + runcShim + "\"\n"
	if err := os.WriteFile(mainConfig, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, mainConfig
}

func TestCheckRejectsUnwrappedHandlers(t *testing.T) {
	const runcOptions = "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\n"
	tests := []struct {
		name    string
		dropIns map[string]string
		wantErr string
	}{
		{
			name:    "no drop-in leaves BinaryName empty, which is PATH runc",
			dropIns: map[string]string{},
			wantErr: "resolves runc through PATH",
		},
		{
			name:    "an empty BinaryName is rejected",
			dropIns: map[string]string{"10-c8s-runc.toml": runcOptions + `BinaryName = ""` + "\n"},
			wantErr: "resolves runc through PATH",
		},
		{
			name:    "an alternate runc is rejected",
			dropIns: map[string]string{"10-c8s-runc.toml": runcOptions + `BinaryName = "/usr/bin/runc"` + "\n"},
			wantErr: "want the measured wrapper",
		},
		{
			name: "a later drop-in unwrapping the handler is rejected",
			dropIns: map[string]string{
				"10-c8s-runc.toml": runcOptions + `BinaryName = "` + wrapper + `"` + "\n",
				"zz-operator.toml": runcOptions + `BinaryName = "/var/lib/rancher/rke2/bin/runc"` + "\n",
			},
			wantErr: "want the measured wrapper",
		},
		{
			name: "an unaudited shim is rejected",
			dropIns: map[string]string{
				"10-c8s-runc.toml": runcOptions + `BinaryName = "` + wrapper + `"` + "\n",
				"20-wasm.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.spin]\n" +
					`runtime_type = "io.containerd.spin.v2"` + "\n",
			},
			wantErr: "unaudited shim",
		},
		{
			name: "default_runtime_name must name a wrapped handler",
			dropIns: map[string]string{
				"10-c8s-runc.toml": runcOptions + `BinaryName = "` + wrapper + `"` + "\n",
				"20-default.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd]\n" +
					`default_runtime_name = "runhcs-wcow-process"` + "\n",
			},
			wantErr: "default_runtime_name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, mainConfig := buildConfigDir(t, tt.dropIns)
			cfg, err := effectiveConfig(dir, mainConfig)
			if err != nil {
				t.Fatalf("effectiveConfig = %v", err)
			}
			_, err = checkHandlers(cfg, wrapper)
			if err == nil {
				t.Fatalf("checkHandlers accepted %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("checkHandlers = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestKataHandlerIsRejectedBesideAWrappedRunc(t *testing.T) {
	dir, mainConfig := buildConfigDir(t, map[string]string{
		"10-c8s-runc.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\n" +
			`BinaryName = "` + wrapper + `"` + "\n",
		"20-kata.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.kata-qemu-tdx]\n" +
			`runtime_type = "io.containerd.kata-qemu-tdx.v2"` + "\n",
	})
	cfg, err := effectiveConfig(dir, mainConfig)
	if err != nil {
		t.Fatalf("effectiveConfig = %v", err)
	}
	if _, err := checkHandlers(cfg, wrapper); err == nil || !strings.Contains(err.Error(), `unaudited shim "io.containerd.kata-qemu-tdx.v2"`) {
		t.Fatalf("checkHandlers = %v, want an unaudited shim error for kata", err)
	}
}

// Without an import of exactly the drop-ins this check merges, either the
// wrapper's BinaryName never reaches containerd or containerd reads a drop-in
// nothing here checked.
func TestConfigImportingOtherThanTheMergedDropInsFails(t *testing.T) {
	const merged = "/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/*.toml"
	for name, cfg := range map[string]map[string]any{
		"no imports":        {"version": int64(3)},
		"another directory": {"imports": []any{"/etc/containerd/other.d/*.toml"}},
		"another suffix":    {"imports": []any{"/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/*.json"}},
		"a second import":   {"imports": []any{merged, "/etc/containerd/other.d/*.toml"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkImports(cfg); err == nil || !strings.Contains(err.Error(), "want") {
				t.Fatalf("checkImports(%v) = %v, want an error naming the merged drop-ins", cfg, err)
			}
		})
	}
}

// The command line the lint workflow runs, positive and negative, plus the
// usage errors: every exit status the gate can produce.
func TestRun(t *testing.T) {
	const runcOptions = "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\n"
	unwrapped, unwrappedConfig := buildConfigDir(t, map[string]string{"10-c8s-runc.toml": runcOptions + `BinaryName = "/usr/bin/runc"` + "\n"})
	broken, brokenConfig := buildConfigDir(t, map[string]string{"10-c8s-runc.toml": "not = [toml\n"})
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "baked image passes",
			args:       []string{"-config-dir", bakedConfigDir, "-config", bakedConfig},
			wantStdout: "every ordinary-pod handler runs " + wrapper + ": runc",
		},
		{
			name:       "unwrapped handler fails",
			args:       []string{"-config-dir", unwrapped, "-config", unwrappedConfig},
			wantCode:   1,
			wantStderr: "want the measured wrapper",
		},
		{
			name:       "malformed drop-in fails",
			args:       []string{"-config-dir", broken, "-config", brokenConfig},
			wantCode:   1,
			wantStderr: "parse drop-in",
		},
		{
			name:       "missing config dir is a usage error",
			args:       nil,
			wantCode:   2,
			wantStderr: "-config-dir and -config are required",
		},
		{
			name:       "missing main config is a usage error",
			args:       []string{"-config-dir", bakedConfigDir},
			wantCode:   2,
			wantStderr: "-config-dir and -config are required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.wantCode {
				t.Fatalf("run(%v) = %d, want %d\nstdout: %s\nstderr: %s", tt.args, code, tt.wantCode, &stdout, &stderr)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("run(%v) stdout = %q, want it to contain %q", tt.args, &stdout, tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("run(%v) stderr = %q, want it to contain %q", tt.args, &stderr, tt.wantStderr)
			}
		})
	}
}
