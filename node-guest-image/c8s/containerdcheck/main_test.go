package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wrapper = "/usr/local/bin/c8s-runc"

// bakedConfigDir is the profile's containerd directory, the one the CI gate
// checks.
const bakedConfigDir = "../mkosi.extra/var/lib/rancher/rke2/agent/etc/containerd"

// The image as committed must pass: RKE2's own base template and the baked
// drop-ins.
func TestBakedConfigWrapsEveryHandler(t *testing.T) {
	cfg, err := effectiveConfig(bakedConfigDir, nil)
	if err != nil {
		t.Fatalf("effectiveConfig(baked) = %v", err)
	}
	handlers, err := checkHandlers(cfg, wrapper)
	if err != nil {
		t.Fatalf("checkHandlers(baked) = %v", err)
	}
	if len(handlers) == 0 || handlers[0] != "runc" {
		t.Fatalf("wrapped handlers = %v, want the runc handler", handlers)
	}
}

// RKE2 adds a handler for every runtime binary it finds on PATH. None of them
// is wrapped, so the gate must fail rather than publish the image.
func TestAutoDetectedRuntimeFails(t *testing.T) {
	for name, binary := range map[string]string{
		"crun":   "/usr/bin/crun",
		"nvidia": "/usr/local/nvidia/toolkit/nvidia-container-runtime",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := effectiveConfig(bakedConfigDir, extraRuntimes{name: binary})
			if err != nil {
				t.Fatalf("effectiveConfig = %v", err)
			}
			if _, err := checkHandlers(cfg, wrapper); err == nil {
				t.Fatalf("checkHandlers accepted an auto-detected %s handler", name)
			}
		})
	}
}

// buildConfigDir writes the drop-ins and returns the directory. Like the
// profile, it bakes no user template.
func buildConfigDir(t *testing.T, dropIns map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	dropInDir := filepath.Join(dir, dropInDirName)
	if err := os.MkdirAll(dropInDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range dropIns {
		if err := os.WriteFile(filepath.Join(dropInDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
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
			dir := buildConfigDir(t, tt.dropIns)
			cfg, err := effectiveConfig(dir, nil)
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
	dir := buildConfigDir(t, map[string]string{
		"10-c8s-runc.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\n" +
			`BinaryName = "` + wrapper + `"` + "\n",
		"20-kata.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.kata-qemu-tdx]\n" +
			`runtime_type = "io.containerd.kata-qemu-tdx.v2"` + "\n",
	})
	cfg, err := effectiveConfig(dir, nil)
	if err != nil {
		t.Fatalf("effectiveConfig = %v", err)
	}
	if _, err := checkHandlers(cfg, wrapper); err == nil || !strings.Contains(err.Error(), `unaudited shim "io.containerd.kata-qemu-tdx.v2"`) {
		t.Fatalf("checkHandlers = %v, want an unaudited shim error for kata", err)
	}
}

// A baked user template replaces the base as the root of the render, so one
// that does not include the base loses the drop-in import and fails.
func TestUserTemplateWithoutBaseFails(t *testing.T) {
	dir := buildConfigDir(t, map[string]string{
		"10-c8s-runc.toml": "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\n" +
			`BinaryName = "` + wrapper + `"` + "\n",
	})
	if err := os.WriteFile(filepath.Join(dir, userTemplateName), []byte("version = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := effectiveConfig(dir, nil); err == nil || !strings.Contains(err.Error(), "no import matching") {
		t.Fatalf("effectiveConfig(user template without base) = %v, want an error about the missing import", err)
	}
}

// Without the drop-in import the wrapper's BinaryName never reaches
// containerd, however correct the drop-in itself is. The import comes from
// RKE2's base template, so a re-vendor that lost it must fail here.
func TestConfigWithoutDropInImportFails(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"no imports":      {"version": int64(3)},
		"other imports":   {"imports": []any{"/etc/containerd/other.d/*.toml"}},
		"import not toml": {"imports": []any{"/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.d/*.json"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkImports(cfg); err == nil || !strings.Contains(err.Error(), "no import matching") {
				t.Fatalf("checkImports(%v) = %v, want an error about the missing import", cfg, err)
			}
		})
	}
}

// The command line the lint workflow runs, positive and negative, plus the
// usage errors: every exit status the gate can produce.
func TestRun(t *testing.T) {
	const runcOptions = "[plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.runc.options]\n"
	unwrapped := buildConfigDir(t, map[string]string{"10-c8s-runc.toml": runcOptions + `BinaryName = "/usr/bin/runc"` + "\n"})
	broken := buildConfigDir(t, map[string]string{"10-c8s-runc.toml": "not = [toml\n"})
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "baked image passes",
			args:       []string{"-config-dir", bakedConfigDir},
			wantStdout: "every ordinary-pod handler runs " + wrapper + ": runc",
		},
		{
			name:       "auto-detected runtime fails",
			args:       []string{"-config-dir", bakedConfigDir, "-extra-runtime", "crun=/usr/bin/crun"},
			wantCode:   1,
			wantStderr: "::error::",
		},
		{
			name:       "unwrapped handler fails",
			args:       []string{"-config-dir", unwrapped},
			wantCode:   1,
			wantStderr: "want the measured wrapper",
		},
		{
			name:       "malformed drop-in fails",
			args:       []string{"-config-dir", broken},
			wantCode:   1,
			wantStderr: "parse drop-in",
		},
		{
			name:       "missing config dir is a usage error",
			args:       nil,
			wantCode:   2,
			wantStderr: "-config-dir is required",
		},
		{
			name:       "malformed extra runtime is a usage error",
			args:       []string{"-config-dir", bakedConfigDir, "-extra-runtime", "crun"},
			wantCode:   2,
			wantStderr: "want NAME=BINARY",
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
