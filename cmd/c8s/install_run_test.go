//go:build !c8s_node

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// mustRunNoMutation asserts the run left the cluster as it found it.
func mustRunNoMutation(t *testing.T, calls []string) {
	t.Helper()
	for _, prefix := range []string{"kubectl apply", "kubectl patch", "helm upgrade"} {
		mustNotContainPrefix(t, calls, prefix)
	}
}

// lastLineIndex returns the index of the last logged line with the prefix, or -1.
func lastLineIndex(lines []string, prefix string) int {
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], prefix) {
			return i
		}
	}
	return -1
}

// kubectlCalls are the logged kubectl invocations alone.
func kubectlCalls(lines []string) []string {
	var out []string
	for _, line := range lines {
		if strings.HasPrefix(line, "kubectl ") {
			out = append(out, line)
		}
	}
	return out
}

// valuesFileArgs are the -f paths of one logged helm invocation, in argv order.
func valuesFileArgs(call string) []string {
	args := strings.Fields(call)
	var files []string
	for i, arg := range args {
		if arg == "-f" && i+1 < len(args) {
			files = append(files, args[i+1])
		}
	}
	return files
}

// flagValue is the token after flag in one logged invocation.
func flagValue(call, flag string) string {
	args := strings.Fields(call)
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// helmSeedRenderCapture re-stubs helm so a `template` copies its last -f file to capture.
func helmSeedRenderCapture(t *testing.T, s *installStubs, capture string) {
	t.Helper()
	s.f.tool(t, "helm", `case "$1" in
show) /bin/cat "$3/values.yaml" ;;
pull) `+helmPullBody(s.release)+` ;;
template)
  prev=; last=
  for a in "$@"; do
    if [ "$prev" = "-f" ]; then last="$a"; fi
    prev="$a"
  done
  if [ -n "$last" ]; then /bin/cp "$last" '`+capture+`'; fi
  /bin/echo '`+installSeedConfigMap+`' ;;
esac`)
}

// The seed render reads the cluster's version and nothing else of it, and renders with the
// computed values the install would apply.
func TestInstallSeedOnlyRunRendersWithTheComputedValues(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
	capture := filepath.Join(s.f.dir, "seed-render-values.yaml")
	helmSeedRenderCapture(t, s, capture)
	out := filepath.Join(t.TempDir(), "seed.json")

	if err := runC8s(t, "install", "--platform=aks-snp", flagArg(flagSeedOut), out); err != nil {
		t.Fatalf("install: %v", err)
	}

	calls := s.f.calls(t)
	if got := kubectlCalls(calls); !slices.Equal(got, []string{"kubectl version -o json"}) {
		t.Errorf("kubectl calls = %v, want the cluster version read alone", got)
	}
	mustRunNoMutation(t, calls)

	render := lineIndex(calls, "helm template ")
	if render < 0 {
		t.Fatalf("no helm template logged:\n%s", strings.Join(calls, "\n"))
	}
	files := valuesFileArgs(calls[render])
	if len(files) < 2 || !strings.HasPrefix(filepath.Base(files[len(files)-1]), "c8s-install-values-") {
		t.Fatalf("the seed render reads -f %v, want the computed values file last", files)
	}
	tree := readYAMLTree(t, capture)
	for _, image := range [][]string{
		{"armtlsMesh", "image"},
		{"attestationApi", "image"},
		{"image"},
		{"nriImagePolicy", "image"},
		{"volumed", "image"},
	} {
		if got := treeAt(t, tree, append(image, "digest")...); got != testDigest {
			t.Errorf("the render's computed values %v.digest = %#v, want the release digest %s", image, got, testDigest)
		}
	}

	document, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pkgallowlist.ParseJSON(document)
	if err != nil {
		t.Fatalf("the written seed does not parse: %v\n%s", err, document)
	}
	entry, ok := seed.Workloads[installSeedEntryName]
	if !ok || len(entry.Containers) != 1 || entry.Containers[0].Digest.String() != "sha256:"+testSeedDigest {
		t.Fatalf("written seed = %v, want the rendered entry at the digest the render carries", seed.Workloads)
	}
}

// Every refusal that reads the cluster leaves it untouched: the containerd restart the
// release triggers is not something half an install survives.
func TestInstallRefusalsRunNoMutatingCommand(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, s *installStubs) []string
		wantErr string
	}{
		{
			name: "containerd below the NRI container user",
			setup: func(t *testing.T, s *installStubs) []string {
				s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `*containerRuntimeVersion*) /usr/bin/printf 'node-a\tcontainerd://2.2.7\n' ;;
`))
				return nil
			},
			wantErr: "node-a (containerd://2.2.7)",
		},
		{
			name: "a distribution bundled containerd",
			setup: func(t *testing.T, s *installStubs) []string {
				s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `*kubeletVersion*) /usr/bin/printf 'node-a\tv1.29.5+rke2r1\n' ;;
`))
				return nil
			},
			wantErr: "upstream containerd",
		},
		{
			name: "the router host port taken on every node",
			setup: func(t *testing.T, s *installStubs) []string {
				pods := podListFile(t, hostPortPod("kube-system", "ingress-a", "node-a", 443))
				s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get pods --all-namespaces -o json") /bin/cat '`+pods+`' ;;
`))
				return nil
			},
			wantErr: "kube-system/ingress-a",
		},
		{
			name: "no confidential node",
			setup: func(t *testing.T, s *installStubs) []string {
				s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get nodes -l "*'{.metadata.name}{"\n"}'*) ;;
`))
				return nil
			},
			wantErr: aksConfidentialNodeSelector,
		},
		{
			name: "a policy denying a platform pod",
			setup: func(t *testing.T, s *installStubs) []string {
				s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, staticEtcdPod()))
				return []string{"-f", writeValuesFile(t, "nriImagePolicy:\n  policy:\n    exemptNamespaces: []\n")}
			},
			wantErr: "kube-system/etcd-node-a",
		},
		{
			name: "a platform image under no exempt repository",
			setup: func(t *testing.T, s *installStubs) []string {
				uncovered := daemonSetPod("kube-system", "fluentbit-a", "example.test/fluentbit:v1",
					"example.test/fluentbit@sha256:"+strings.Repeat("55", 32))
				uncovered.Spec.NodeName = "node-a"
				s.f.tool(t, "kubectl", platformPodListKubectl(t, s.applied, uncovered))
				return nil
			},
			wantErr: "kube-system/fluentbit-a",
		},
		{
			name: "a route flag with no route to write",
			setup: func(t *testing.T, s *installStubs) []string {
				s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))
				return []string{flagArg(flagOperatorKey), "op.pem"}
			},
			wantErr: "pass --" + flagUpstream,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newInstallStubs(t, "", false)
			args := tc.setup(t, s)
			err := runInstall(t, append([]string{"--platform=aks-snp", "--wait=false"}, args...)...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("install = %v, want an error containing %q", err, tc.wantErr)
			}
			mustRunNoMutation(t, s.f.calls(t))
		})
	}
}

// A router.san a route manifest cannot name is a front door --upstream cannot route for.
func TestInstallUpstreamRefusesASANWithNoDNSName(t *testing.T) {
	deploy := deploymentFile(t, "ghcr.io/acme/vllm@"+testDigest)
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get deployment vllm -n ws -o json") /bin/cat '`+deploy+`' ;;
`))
	values := writeValuesFile(t, "router:\n  san:\n    - '*.example.com'\n    - 192.0.2.5\n")

	var err error
	stderr := captureStderr(t, func() {
		err = runInstall(t, "--platform=aks-snp", "-f", values,
			flagArg(flagWorkloadRef), "infer=ws/deployment/vllm:8000", flagArg(flagUpstream), "infer",
			"--routes-out", filepath.Join(t.TempDir(), "routes.json"))
	})
	if err == nil || !strings.Contains(err.Error(), "needs a DNS name in router.san") {
		t.Fatalf("install = %v, want the refusal naming router.san", err)
	}
	if !strings.Contains(stderr, `router.san entry "*.example.com"`) {
		t.Errorf("stderr warns about no skipped router.san entry:\n%s", stderr)
	}
	mustNotContainPrefix(t, s.f.calls(t), "helm upgrade")
}

// The cluster-side pull credential is the release's to use, not the install's to create.
func TestInstallRefusesAMissingImagePullSecretBeforeTheCluster(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get secret regcred -n c8s-system -o json") echo 'Error from server (NotFound): secrets "regcred" not found' >&2; exit 1 ;;
`))
	err := runInstall(t, "--platform=aks-snp", "--wait=false", "--force", "--image-pull-secret", "regcred")
	if err == nil || !strings.Contains(err.Error(), "kubectl create secret docker-registry") {
		t.Fatalf("install = %v, want the missing-secret refusal naming the creation command", err)
	}
	mustRunNoMutation(t, s.f.calls(t))
}

// An install that leaves its temp files behind leaves a CDS pin and a values file in /tmp.
func TestInstallRemovesTheFilesItCreated(t *testing.T) {
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, ""))

	resetCLIState(t)
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	rootCmd.SetIn(strings.NewReader(pipedCDS(t)))
	rootCmd.SetArgs([]string{"install", "--platform=aks-snp", "--wait=false", "-f", "-"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("install: %v", err)
	}

	calls := s.f.calls(t)
	upgrade, pull := lineIndex(calls, "helm upgrade "), lineIndex(calls, "helm pull ")
	if upgrade < 0 || pull < 0 {
		t.Fatalf("install did not pull and upgrade:\n%s", strings.Join(calls, "\n"))
	}
	files := valuesFileArgs(calls[upgrade])
	if len(files) < 3 {
		t.Fatalf("helm upgrade read -f %v, want the stock, the piped and the computed values", files)
	}
	stdinValues := ""
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), "c8s-install-stdin-") {
			stdinValues = f
		}
	}
	pin := ""
	if installCDS != nil {
		pin = installCDS.path
	}
	for _, tmp := range []struct{ name, path, prefix string }{
		{"stdin values file", stdinValues, "c8s-install-stdin-"},
		{"CDS pin copy", pin, "c8s-cds-pin-"},
		{"work directory", filepath.Dir(flagValue(calls[pull], "--untardir")), "c8s-install-"},
		{"computed values file", files[len(files)-1], "c8s-install-values-"},
	} {
		if !strings.HasPrefix(filepath.Base(tmp.path), tmp.prefix) {
			t.Errorf("the install named no %s (%q), so this run says nothing about removing it", tmp.name, tmp.path)
			continue
		}
		if _, err := os.Stat(tmp.path); !os.IsNotExist(err) {
			t.Errorf("install left its %s %s behind (stat: %v)", tmp.name, tmp.path, err)
		}
	}
}

// The cluster read precedes the registry, and the reads the adopted-entry check judges
// precede the release it would otherwise be too late to refuse.
func TestInstallOrdersTheClusterReadAndTheAdoptionCheckFirst(t *testing.T) {
	deploy := deploymentFile(t, "ghcr.io/acme/vllm@"+testDigest)
	s := newInstallStubs(t, "", false)
	s.f.tool(t, "kubectl", clusterKubectl(t, s.applied, `"get deployment vllm -n ws -o json") /bin/cat '`+deploy+`' ;;
`))
	if err := runInstall(t, "--platform=aks-snp", "--force", flagArg(flagWorkloadRef), "infer=ws/deployment/vllm"); err != nil {
		t.Fatalf("install: %v", err)
	}

	calls := s.f.calls(t)
	version, pull := lineIndex(calls, "kubectl version "), lineIndex(calls, "helm pull ")
	if version < 0 || pull < 0 || version > pull {
		t.Errorf("kubectl version at %d, helm pull at %d, want the cluster read first", version, pull)
	}
	upgrade := lineIndex(calls, "helm upgrade ")
	template := lineIndex(calls, "kubectl get deployment vllm -n ws -o json")
	rendered := lastLineIndex(calls, "helm show values ")
	if upgrade < 0 || template < 0 || rendered < 0 || template > upgrade || rendered > upgrade {
		t.Errorf("adopted template read at %d and rendered values at %d, want both before helm upgrade at %d",
			template, rendered, upgrade)
	}
}
