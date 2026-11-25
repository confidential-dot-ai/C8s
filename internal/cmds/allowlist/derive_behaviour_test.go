package allowlist

import (
	"bytes"
	"io"
	"maps"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// deriveOutput runs derive and returns its stdout and stderr verbatim.
func deriveOutput(t *testing.T, stdin string, args ...string) (string, string) {
	t.Helper()
	cmd := newDeriveCmd(&options{})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("derive: %v", err)
	}
	return out.String(), errOut.String()
}

func TestDeriveYAMLMatchesJSON(t *testing.T) {
	const input = `{"kind":"Pod","spec":{"containers":[{"name":"web","image":"` + testImage + `","command":["/app"],"args":["yes","hello \ud83c\udf0d"]}]}}`
	const yamlInput = `# workload
---
kind: Pod
spec:
  containers:
    - name: web
      image: ` + testImage + `
      command: [/app]
      args:
        - "yes"
        - |-
          hello 🌍
...
`
	want, wantWarnings := deriveOutput(t, input, "app", "-", "--env=any")
	for _, tc := range []struct{ source, stdin string }{
		{"-", yamlInput},
		{writeFile(t, "workload.yaml", yamlInput), ""},
	} {
		got, warnings := deriveOutput(t, tc.stdin, "app", tc.source, "--env=any")
		if got != want || warnings != wantWarnings {
			t.Errorf("derive from %s produced entry %s and warnings %q; want %s and %q", tc.source, got, warnings, want, wantWarnings)
		}
	}
}

func TestQuotedYAMLAnnotationKeys(t *testing.T) {
	const manifest = `metadata:
  annotations: {"on": first, !!str no: second, "true": third, 1: fourth}
spec:
  containers: [{name: web}]
`
	spec, err := podSpecOf([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"on": "first", "no": "second", "true": "third", "1": "fourth"}
	if !maps.Equal(spec.annotations, want) {
		t.Errorf("annotations = %v, want %v", spec.annotations, want)
	}
}

func TestDeriveMatchesKubernetesFieldNames(t *testing.T) {
	const manifest = `kind: Pod
spec:
  initContainers: [{name: seed, image: ` + testImage + `, command: [/seed]}]
  initcontainers: []
  containers: [{name: web, image: ` + testImage + `, command: [/app]}]
`
	entries, err := runDerive(t, manifest, "web", "-", "--env=any")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(entries["web"].InitContainers); got != 1 {
		t.Errorf("derived %d init containers, want 1", got)
	}
}

func TestDeriveRejectsInvalidManifest(t *testing.T) {
	const pod = "kind: Pod\nspec:\n  containers:\n    - name: web\n      image: " + testImage + "\n      command: [/app]\n"
	for _, tc := range []struct{ name, input, wantErr string }{
		{"two workloads", pod + "---\n" + pod, "exactly one"},
		{"empty second document", pod + "---\n", "exactly one"},
		{"concatenated JSON", deployJSON() + "\n" + deployJSON(), "parse object"},
		{"trailing text", pod + "...\ntrailing garbage", "parse object"},
		{"duplicate image", pod + "      image: " + testImage + "\n", "image"},
		{"merge key", pod + "      <<: {args: [hello]}\n", "mapping key"},
		{"anchor", pod + "      args: &greeting [hello]\n", "anchor"},
		{"alias", strings.Replace(pod, "command: [/app]", "command: &argv [/app]\n      args: *argv", 1), "anchor"},
		{"non-scalar key", pod + "metadata:\n  annotations: {[a, b]: value}\n", "mapping key"},
		{"duplicate annotation", pod + "metadata:\n  annotations: {1: first, \"1\": second}\n", "duplicate"},
		{"ambiguous boolean key", pod + "metadata:\n  annotations: {on: first, \"true\": second}\n", "quote"},
		{"duplicate JSON field", strings.Replace(deployJSON(), `"image":`, `"image":"other","image":`, 1), "duplicate"},
		{"boolean argument", pod + "      args: [yes]\n", "bool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewCmd()
			var stdout bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(io.Discard)
			cmd.SetIn(strings.NewReader(tc.input))
			cmd.SetArgs([]string{"derive", "app", "-", "--env=any"})
			err := cmd.Execute()
			if stdout.Len() != 0 {
				t.Errorf("derive wrote %q to stdout on invalid input", stdout.String())
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("derive error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// injectedPodJSON is an admitted pod: an injected init and main container, an
// authored main that runs as uid 0, and a secrets annotation naming none.
func injectedPodJSON() string {
	return `{
      "kind": "Pod",
      "metadata": {"annotations": {"confidential.ai/c8s-secrets": " ,\n "}},
      "spec": {
        "securityContext": {"runAsUser": 1000},
        "initContainers": [
          {"name": "c8s-cert", "image": "ghcr.io/confidential-dot-ai/c8s:v0.23.0"},
          {"name": "seed", "image": "` + testImage + `", "command": ["sh"]}
        ],
        "containers": [
          {"name": "app", "image": "` + testImage + `", "command": ["sleep", "inf"],
           "securityContext": {"runAsUser": 0}},
          {"name": "c8s-mesh", "image": "ghcr.io/confidential-dot-ai/c8s:v0.23.0"}
        ]}}`
}

func TestDeriveEnvFileMustNameEveryDerivedContainer(t *testing.T) {
	for _, tc := range []struct{ name, file, wantErr string }{
		{"init container omitted", `{"frontend":{"policy":"any"},"worker":{"policy":"any"}}`, `missing env policy for container "seed"`},
		{"main container omitted", `{"seed":{"policy":"deny"},"worker":{"policy":"any"}}`, `missing env policy for container "frontend"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runDerive(t, deployJSON(), "dynamo", "-", "--env-file", writeFile(t, "env.json", tc.file))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("derive error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestDeriveEnvFileReachesEveryDerivedContainer(t *testing.T) {
	file := writeFile(t, "env.json", `{"seed":{"policy":"exact","values":{"ROLE":"seed"}},"frontend":{"policy":"deny"},"worker":{"policy":"any"}}`)
	got, err := runDerive(t, deployJSON(), "dynamo", "-", "--env-file", file)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	w := got["dynamo"]
	if env := w.InitContainers[0].Env; env.Policy != pkgallowlist.PolicyExact || env.Values["ROLE"] != "seed" {
		t.Errorf("seed env = %+v, want the exact policy the file names", env)
	}
	if p := w.Containers[0].Env.Policy; p != pkgallowlist.PolicyDeny {
		t.Errorf("frontend env policy = %q, want %q", p, pkgallowlist.PolicyDeny)
	}
	if p := w.Containers[1].Env.Policy; p != pkgallowlist.PolicyAny {
		t.Errorf("worker env policy = %q, want %q", p, pkgallowlist.PolicyAny)
	}
}

func TestDeriveEmptyPolicyFileNamesTheFirstContainer(t *testing.T) {
	for _, tc := range []struct{ name, flag, wantErr string }{
		{"env", "--env-file", `missing env policy for container "seed"`},
		{"mounts", "--mounts-file", `missing mount policy for container "seed"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"dynamo", "-", tc.flag, writeFile(t, "policy.json", `{}`)}
			if tc.flag == "--mounts-file" {
				args = append(args, "--env=any")
			}
			if _, err := runDerive(t, deployJSON(), args...); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("derive error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestDeriveWritesTheWholeEntryToStdout(t *testing.T) {
	stdout, _ := deriveOutput(t, podJSON(t, nil, nil, nil), "app", "-", "--env=any")
	const want = `{
  "app": {
    "initContainers": [
      {
        "digest": "sha256:effd250754b8a70517c27eab8f18463b395a7b2a8e868fd919226c3180636939",
        "image": "nvcr.io/nvidia/ai-dynamo/vllm-runtime@sha256:effd250754b8a70517c27eab8f18463b395a7b2a8e868fd919226c3180636939",
        "command": {
          "policy": "exact",
          "argv": [
            "sh"
          ]
        },
        "args": {
          "policy": "deny"
        },
        "mounts": {
          "policy": ""
        },
        "env": {
          "policy": "any"
        }
      }
    ],
    "containers": [
      {
        "digest": "sha256:effd250754b8a70517c27eab8f18463b395a7b2a8e868fd919226c3180636939",
        "image": "nvcr.io/nvidia/ai-dynamo/vllm-runtime@sha256:effd250754b8a70517c27eab8f18463b395a7b2a8e868fd919226c3180636939",
        "command": {
          "policy": "exact",
          "argv": [
            "sleep",
            "inf"
          ]
        },
        "args": {
          "policy": "deny"
        },
        "mounts": {
          "policy": ""
        },
        "env": {
          "policy": "any"
        }
      }
    ]
  }
}
`
	if stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout, want)
	}
}

func TestDeriveReportsEveryFindingOnStderr(t *testing.T) {
	_, stderr := deriveOutput(t, injectedPodJSON(), "app", "-", "--env=any")
	const want = `dropped c8s-cert, c8s-mesh: injected by c8s
container "app" does not state a nonzero uid, and a C8s node refuses a container that runs as uid 0: set a nonzero runAsUser, or runAsNonRoot: true if its image's USER is a nonzero uid
mounts: no policy given; every container is "deny", which admits platform mounts alone
`
	if stderr != want {
		t.Errorf("stderr:\n%s\nwant:\n%s", stderr, want)
	}
}

func TestDeriveDropsAnInjectedMainContainer(t *testing.T) {
	pod := `{"kind":"Pod","spec":{"securityContext":{"runAsUser":1000},"containers":[
      {"name":"app","image":"` + testImage + `","command":["sleep","inf"]},
      {"name":"c8s-mesh","image":"ghcr.io/confidential-dot-ai/c8s:v0.23.0"}]}}`
	got, stderr, err := runDeriveStderr(t, pod, "app", "-", "--env=any", "--mounts=any")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got["app"].Containers) != 1 {
		t.Fatalf("containers = %d, want only the authored app", len(got["app"].Containers))
	}
	if !equalArgv(got["app"].Containers[0].Command.Argv, []string{"sleep", "inf"}) {
		t.Errorf("command = %v, want the app argv", got["app"].Containers[0].Command.Argv)
	}
	if stderr != "dropped c8s-mesh: injected by c8s\n" {
		t.Errorf("stderr = %q, want the injected main container named", stderr)
	}
}
