package getkubeconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func vmiWithStatus(status map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "kubevirt.io/v1",
		"kind":       "VirtualMachineInstance",
		"metadata": map[string]any{
			"name":      "mn-server",
			"namespace": "confai-images",
		},
	}
	if status != nil {
		obj["status"] = status
	}
	return &unstructured.Unstructured{Object: obj}
}

func TestVMIAddress(t *testing.T) {
	cases := []struct {
		name    string
		status  map[string]any
		want    string
		wantErr string
	}{
		{
			name: "first interface wins",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": "10.42.0.158"},
				map[string]any{"ipAddress": "10.42.0.201"},
			}},
			want: "10.42.0.158",
		},
		{
			// A booting guest can report an interface before its address.
			name: "address-less interface is skipped",
			status: map[string]any{"interfaces": []any{
				map[string]any{"name": "default"},
				map[string]any{"ipAddress": "10.42.0.201"},
			}},
			want: "10.42.0.201",
		},
		{
			// A malformed object surfaces the read error, not no-address.
			name:    "interfaces of the wrong type",
			status:  map[string]any{"interfaces": "bogus"},
			wantErr: "read status.interfaces",
		},
		{
			name: "non-map interface entry is skipped",
			status: map[string]any{"interfaces": []any{
				"bogus",
				map[string]any{"ipAddress": "10.42.0.201"},
			}},
			want: "10.42.0.201",
		},
		{
			name: "IPv6 address",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": "fd00::5"},
			}},
			want: "fd00::5",
		},
		{
			// Fail closed: a bad first address is not skipped for a later one.
			name: "injected YAML is refused",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": "10.0.0.5\n    insecure-skip-tls-verify: true"},
				map[string]any{"ipAddress": "10.42.0.201"},
			}},
			wantErr: `guest confai-images/mn-server reports address "10.0.0.5\n    insecure-skip-tls-verify: true", which is not an IP`,
		},
		{
			name: "hostname is refused",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": "evil.example"},
			}},
			wantErr: "which is not an IP",
		},
		{
			name: "long value is truncated",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": strings.Repeat("a", 64) + "TAIL"},
			}},
			wantErr: `"` + strings.Repeat("a", 64) + `", which is not an IP`,
		},
		{
			name:    "no status",
			status:  nil,
			wantErr: "no reported address",
		},
		{
			name:    "empty interfaces",
			status:  map[string]any{"interfaces": []any{}},
			wantErr: "no reported address",
		},
		{
			name: "empty ipAddress",
			status: map[string]any{"interfaces": []any{
				map[string]any{"ipAddress": ""},
			}},
			wantErr: "no reported address",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vmiAddress(vmiWithStatus(tc.status))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("vmiAddress: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestResolveVMIRejectsMalformedRefs(t *testing.T) {
	// Ref validation runs before any kubeconfig or cluster access, so these
	// fail fast with the ref error regardless of the test environment.
	for _, ref := range []string{"", "/mn-server", "confai-images/", "/"} {
		if _, err := resolveVMI(context.Background(), ref); err == nil ||
			!strings.Contains(err.Error(), "is not name or namespace/name") {
			t.Fatalf("ref %q: want malformed-ref error, got %v", ref, err)
		}
	}
}

// fakeVMIClient stubs newVMIClient with a fake dynamic client holding the
// given objects and reporting contextNS as the kubeconfig context namespace.
func fakeVMIClient(t *testing.T, contextNS string, objects ...runtime.Object) {
	t.Helper()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: "VirtualMachineInstanceList"},
		&unstructured.UnstructuredList{})
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{vmiGVR: "VirtualMachineInstanceList"}, objects...)
	restore := newVMIClient
	newVMIClient = func() (dynamic.Interface, string, error) {
		return client, contextNS, nil
	}
	t.Cleanup(func() { newVMIClient = restore })
}

func TestResolveVMI(t *testing.T) {
	t.Run("bare name uses the context namespace", func(t *testing.T) {
		fakeVMIClient(t, "confai-images", vmiWithStatus(map[string]any{
			"interfaces": []any{map[string]any{"ipAddress": "10.42.0.158"}},
		}))
		got, err := resolveVMI(context.Background(), "mn-server")
		if err != nil {
			t.Fatalf("resolveVMI: %v", err)
		}
		if got != "10.42.0.158" {
			t.Fatalf("want 10.42.0.158, got %q", got)
		}
	})

	t.Run("namespace/name overrides the context namespace", func(t *testing.T) {
		fakeVMIClient(t, "elsewhere", vmiWithStatus(map[string]any{
			"interfaces": []any{map[string]any{"ipAddress": "10.42.0.158"}},
		}))
		if _, err := resolveVMI(context.Background(), "confai-images/mn-server"); err != nil {
			t.Fatalf("resolveVMI: %v", err)
		}
	})

	t.Run("missing guest wraps the lookup error", func(t *testing.T) {
		fakeVMIClient(t, "confai-images")
		_, err := resolveVMI(context.Background(), "absent-cvm")
		if err == nil || !strings.Contains(err.Error(), "get virtualmachineinstance confai-images/absent-cvm") {
			t.Fatalf("want wrapped get error, got %v", err)
		}
	})

	t.Run("injected address is refused", func(t *testing.T) {
		fakeVMIClient(t, "confai-images", vmiWithStatus(map[string]any{
			"interfaces": []any{map[string]any{"ipAddress": "10.0.0.5\n    insecure-skip-tls-verify: true"}},
		}))
		got, err := resolveVMIAddress(context.Background(), "mn-server")
		if err == nil || !strings.Contains(err.Error(), "mn-server") || !strings.Contains(err.Error(), "not an IP") {
			t.Fatalf("resolveVMIAddress = %q, %v; want refusal naming the VMI", got, err)
		}
	})

	t.Run("guest without an address fails", func(t *testing.T) {
		fakeVMIClient(t, "confai-images", vmiWithStatus(nil))
		_, err := resolveVMI(context.Background(), "mn-server")
		if err == nil || !strings.Contains(err.Error(), "no reported address") {
			t.Fatalf("want no-address error, got %v", err)
		}
	})

	t.Run("client construction failure propagates", func(t *testing.T) {
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
		_, err := resolveVMI(context.Background(), "mn-server")
		if err == nil || !strings.Contains(err.Error(), "namespace from kubeconfig") {
			t.Fatalf("want kubeconfig error, got %v", err)
		}
	})
}

// TestNewVMIClient exercises the real kubeconfig path: clientcmd loads the
// fixture without contacting a cluster, so the context namespace and client
// construction are fully covered.
func TestNewVMIClient(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- name: outer
  cluster: {server: "https://127.0.0.1:6443"}
users:
- name: op
  user: {}
contexts:
- name: outer
  context: {cluster: outer, user: op, namespace: confai-images}
current-context: outer
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	client, namespace, err := newVMIClient()
	if err != nil {
		t.Fatalf("newVMIClient: %v", err)
	}
	if client == nil {
		t.Fatal("want a client")
	}
	if namespace != "confai-images" {
		t.Fatalf("want context namespace confai-images, got %q", namespace)
	}
}

func TestNewVMIClientFailures(t *testing.T) {
	t.Run("missing kubeconfig", func(t *testing.T) {
		// With no configuration at all, even the namespace read fails.
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
		if _, _, err := newVMIClient(); err == nil ||
			!strings.Contains(err.Error(), "namespace from kubeconfig") {
			t.Fatalf("want namespace error, got %v", err)
		}
	})

	t.Run("context without a usable cluster", func(t *testing.T) {
		// clientcmd validates the whole config on the first read, so even a
		// non-namespace defect like a server-less cluster surfaces there.
		kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- name: outer
  cluster: {}
users:
- name: op
  user: {}
contexts:
- name: outer
  context: {cluster: outer, user: op, namespace: confai-images}
current-context: outer
`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KUBECONFIG", kubeconfig)
		if _, _, err := newVMIClient(); err == nil ||
			!strings.Contains(err.Error(), "namespace from kubeconfig") {
			t.Fatalf("want namespace error, got %v", err)
		}
	})

	t.Run("malformed kubeconfig", func(t *testing.T) {
		kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(kubeconfig, []byte("{not yaml"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KUBECONFIG", kubeconfig)
		// The parse failure surfaces at the first read, the namespace.
		if _, _, err := newVMIClient(); err == nil ||
			!strings.Contains(err.Error(), "namespace from kubeconfig") {
			t.Fatalf("want namespace error, got %v", err)
		}
	})
}
