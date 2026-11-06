package allowlist

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func processNamespaceWorkload(t *testing.T) Workload {
	t.Helper()
	w := Workload{Containers: []Container{
		exactly(t, digestA, "/prefill"),
		exactly(t, digestB, "/decode"),
		exactly(t, digestC, "/metrics"),
	}}
	for i := range w.Containers {
		w.Containers[i].ShareProcessNamespace = i < 2
		w.Containers[i].Mounts.Policy = PolicyDeny
		w.Containers[i].Env.Policy = PolicyDeny
	}
	return w
}

func processNamespaceAllowlist(t *testing.T) *Allowlist {
	t.Helper()
	al := &Allowlist{Schema: ProcessNamespaceSchema, Workloads: map[string]Workload{"pair": processNamespaceWorkload(t)}}
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	return al
}

func processNamespaceLaunch(
	t *testing.T,
	digest string,
	argv string,
	policy string,
) RunningContainer {
	t.Helper()
	env, err := ObserveEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	return RunningContainer{
		Digest: digest, Argv: []string{argv}, Env: env,
		Mounts: []ObservedMount{}, ProcessNamespacePolicy: policy,
	}
}

func TestProcessNamespaceAdmissionBindsTheWholePolicy(t *testing.T) {
	al := processNamespaceAllowlist(t)
	workload := al.Workloads["pair"]
	policy := workload.ProcessNamespacePolicy()
	index := al.BuildIndex()
	prefill := processNamespaceLaunch(t, digestA, "/prefill", policy)
	decode := processNamespaceLaunch(t, digestB, "/decode", policy)
	metrics := processNamespaceLaunch(t, digestC, "/metrics", "")
	if !index.AdmitsContainer(prefill) || !index.AdmitsContainer(decode) || !index.AdmitsContainer(metrics) {
		t.Fatal("the declared shared and private containers must be admitted")
	}
	if name, _, err := al.MatchWorkload([]RunningContainer{prefill, decode, metrics}); err != nil || name != "pair" {
		t.Fatalf("MatchWorkload = %q, %v", name, err)
	}
	for name, launch := range map[string]RunningContainer{
		"missing shared evidence":  processNamespaceLaunch(t, digestA, "/prefill", ""),
		"another group's evidence": processNamespaceLaunch(t, digestA, "/prefill", "sha256:other"),
		"private container joined": processNamespaceLaunch(t, digestC, "/metrics", policy),
	} {
		if index.AdmitsContainer(launch) {
			t.Errorf("admitted %s", name)
		}
		if !index.AdmitsProcess(launch) {
			t.Errorf("preliminary process check must defer namespace evidence: %s", name)
		}
	}
	decode.ProcessNamespacePolicy = "sha256:another-policy"
	if _, _, err := al.MatchWorkload([]RunningContainer{prefill, decode, metrics}); err == nil {
		t.Fatal("matched a workload containing applications from different groups")
	}
	workload.Secrets = &SecretsPolicy{Policy: PolicyAllow, Read: []string{"/different-secret"}}
	if workload.ProcessNamespacePolicy() == policy {
		t.Fatal("changing a secret grant must change the shared group identity")
	}
	decode.ProcessNamespacePolicy = policy
	if workload.Diff([]RunningContainer{prefill, decode, metrics}).Describes() {
		t.Fatal("an old group must not satisfy a workload with a changed grant")
	}
}

func TestProcessNamespaceSelectionReportsConflictingDeclarations(t *testing.T) {
	al := processNamespaceAllowlist(t)
	launch := processNamespaceLaunch(t, digestA, "/prefill", "")
	policy := al.Workloads["pair"].ProcessNamespacePolicy()
	if got := al.BuildIndex().ProcessNamespacePolicies(launch); !slices.Equal(got, []string{policy}) {
		t.Fatalf("ProcessNamespacePolicies = %q, want %q", got, policy)
	}
	private := processNamespaceWorkload(t)
	for i := range private.Containers {
		private.Containers[i].ShareProcessNamespace = false
	}
	al.Workloads["private"] = private
	if got := al.BuildIndex().ProcessNamespacePolicies(launch); !slices.Equal(got, []string{"", policy}) {
		t.Fatalf("shared/private conflict = %q", got)
	}
	other := processNamespaceWorkload(t)
	other.Secrets = &SecretsPolicy{Policy: PolicyAllow, Read: []string{"/another"}}
	al.Workloads["other"] = other
	if got := al.BuildIndex().ProcessNamespacePolicies(launch); len(got) != 3 {
		t.Fatalf("different signed groups must remain separate: %q", got)
	}
	launch.Argv = []string{"/unapproved"}
	if got := al.BuildIndex().ProcessNamespacePolicies(launch); len(got) != 0 {
		t.Fatalf("an unapproved launch has namespace policies %q", got)
	}
}

func TestProcessNamespaceCanonicalRoundTrip(t *testing.T) {
	al := processNamespaceAllowlist(t)
	first, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(first, []byte(`"shareProcessNamespace":true`)) != 2 || bytes.Contains(first, []byte(`"shareProcessNamespace":false`)) {
		t.Fatalf("canonical namespace declarations = %s", first)
	}
	w := al.Workloads["pair"]
	policy := w.ProcessNamespacePolicy()
	slices.Reverse(w.Containers)
	al.Workloads["pair"] = w
	if err := al.Normalize(); err != nil {
		t.Fatal(err)
	}
	second, err := al.Canonical()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("reordered canonical policy differs: %s, %v", second, err)
	}
	parsed, err := ParseJSON(first)
	if err != nil || parsed.Workloads["pair"].ProcessNamespacePolicy() != policy {
		t.Fatalf("policy fingerprint changed on round trip: %v", err)
	}
}

func TestProcessNamespaceRejectsUnpinnedAndPlatformDeclarations(t *testing.T) {
	for name, change := range map[string]func(*Workload){
		"init container": func(w *Workload) {
			w.InitContainers = []Container{w.Containers[0]}
		},
		"platform role": func(w *Workload) { w.Containers[0].Role = "mesh" },
		"exec grant":    func(w *Workload) { w.Containers[0].Execs = [][]string{{"/probe"}} },
		"static pod":    func(w *Workload) { w.StaticPod = true },
		"command": func(w *Workload) {
			w.Containers[0].Command = ArgvPolicy{Policy: PolicyAny}
		},
		"args":        func(w *Workload) { w.Containers[0].Args.Policy = PolicyAny },
		"mounts":      func(w *Workload) { w.Containers[0].Mounts.Policy = PolicyAny },
		"environment": func(w *Workload) { w.Containers[0].Env.Policy = PolicyAny },
		"unselected container": func(w *Workload) {
			w.Containers[2].Env.Policy = PolicyAny
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := processNamespaceWorkload(t)
			change(&w)
			al := &Allowlist{Schema: ProcessNamespaceSchema, Workloads: map[string]Workload{"pair": w}}
			if err := al.Normalize(); err == nil || !strings.Contains(err.Error(), "shareProcessNamespace") {
				t.Fatalf("Normalize = %v, want a namespace sharing refusal", err)
			}
			if name == "platform role" || name == "exec grant" || name == "static pod" {
				return // These fields belong only to the measured YAML base.
			}
			data, err := json.Marshal(w)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseWorkloadJSON(data); err == nil {
				t.Fatal("accepted an unsafe authored namespace sharing policy")
			}
			doc := []byte(`{"schema":"` + ProcessNamespaceSchema + `","workloads":{"pair":` + string(data) + `}}`)
			if _, err := ParseServedJSON(doc); err == nil {
				t.Fatal("accepted an unsafe served namespace sharing policy")
			}
		})
	}
}

func TestProcessNamespaceRequiresTheNewSchema(t *testing.T) {
	al := processNamespaceAllowlist(t)
	al.Schema = Schema
	data, err := json.Marshal(al)
	if err != nil {
		t.Fatal(err)
	}
	for _, parse := range []func([]byte) (*Allowlist, error){ParseJSON, ParseServedJSON} {
		if _, err := parse(data); err == nil || !strings.Contains(err.Error(), ProcessNamespaceSchema) {
			t.Fatalf("old schema parse = %v, want the new schema required", err)
		}
	}
}
