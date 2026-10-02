package workflows

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	exactWorkflow   = "tdx-image-acceptance.yml"
	stagedWorkflow  = "tdx-metal-e2e.yml"
	lifecycleAction = "./.github/actions/tdx-metal-e2e"
)

type workflowStep struct {
	Name, ID, Uses, Run, Shell, If string
	With, Env                      map[string]string
}

type workflowDocument struct {
	On               yaml.Node `yaml:"on"`
	Concurrency      yaml.Node
	Env, Permissions map[string]string
	Jobs             map[string]struct {
		Uses    string
		Needs   yaml.Node
		Outputs map[string]string
		Steps   []workflowStep
	}
}

type lifecycleDocument struct {
	Inputs map[string]struct{ Default yaml.Node }
	Runs   struct {
		Using string
		Steps []workflowStep
	}
}

func readYAML(t *testing.T, path string, out any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func readWorkflow(t *testing.T, name string) workflowDocument {
	t.Helper()
	var doc workflowDocument
	readYAML(t, filepath.Join("../../.github/workflows", name), &doc)
	return doc
}

func events(t *testing.T, node yaml.Node) []string {
	t.Helper()
	var result []string
	switch node.Kind {
	case yaml.ScalarNode:
		result = append(result, node.Value)
	case yaml.SequenceNode:
		for _, event := range node.Content {
			result = append(result, event.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			result = append(result, node.Content[i].Value)
		}
	default:
		t.Fatalf("unsupported workflow trigger shape: %v", node.Kind)
	}
	slices.Sort(result)
	return result
}

// Follow reusable calls, not display names or job conditions: a dispatch/PR
// entrypoint must not gain even a conditionally guarded path to exact checkout.
func TestTDXExactAcceptanceCallerGraph(t *testing.T) {
	paths, err := filepath.Glob("../../.github/workflows/*.y*ml")
	if err != nil {
		t.Fatal(err)
	}
	docs := make(map[string]workflowDocument, len(paths))
	for _, path := range paths {
		docs[filepath.Base(path)] = readWorkflow(t, filepath.Base(path))
	}
	var reaches func(string, map[string]bool) bool
	reaches = func(name string, seen map[string]bool) bool {
		if name == exactWorkflow {
			return true
		}
		if seen[name] {
			return false
		}
		seen[name] = true
		doc, ok := docs[name]
		if !ok {
			t.Fatalf("missing local reusable workflow %s", name)
		}
		for _, job := range doc.Jobs {
			if strings.HasPrefix(job.Uses, "./.github/workflows/") && reaches(filepath.Base(job.Uses), seen) {
				return true
			}
		}
		return false
	}
	var callers []string
	for name, doc := range docs {
		if name == exactWorkflow || !reaches(name, map[string]bool{}) {
			continue
		}
		callers = append(callers, name)
		if got := events(t, doc.On); !reflect.DeepEqual(got, []string{"workflow_run"}) {
			t.Errorf("%s can reach exact acceptance with triggers %v", name, got)
		}
	}
	if !reflect.DeepEqual(callers, []string{"c8s-image-publish.yml"}) {
		t.Fatalf("unexpected exact callers: %v", callers)
	}
	for name, want := range map[string][]string{
		exactWorkflow:          {"workflow_call"},
		"c8s-image-manual.yml": {"workflow_dispatch"},
		stagedWorkflow:         {"workflow_call", "workflow_dispatch"},
	} {
		if got := events(t, docs[name].On); !reflect.DeepEqual(got, want) {
			t.Errorf("%s triggers: got %v want %v", name, got, want)
		}
	}
	var needs []string
	acceptance := docs["c8s-image-publish.yml"].Jobs["verify-tdx-image"]
	if err := acceptance.Needs.Decode(&needs); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(needs, "build-and-push") {
		t.Fatal("image acceptance must depend on publication")
	}
}

func actionCall(t *testing.T, steps []workflowStep) workflowStep {
	t.Helper()
	var calls []workflowStep
	for _, step := range steps {
		if step.Uses == lifecycleAction {
			calls = append(calls, step)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("expected one shared lifecycle call, got %d", len(calls))
	}
	return calls[0]
}

func TestTDXWrappersShareLifecycleIdentity(t *testing.T) {
	exact, staged := readWorkflow(t, exactWorkflow), readWorkflow(t, stagedWorkflow)
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	for _, doc := range []workflowDocument{exact, staged} {
		var concurrency struct {
			Group  string
			Cancel bool `yaml:"cancel-in-progress"`
		}
		if err := doc.Concurrency.Decode(&concurrency); err != nil {
			t.Fatal(err)
		}
		if concurrency.Group != "tdx-metal-e2e" || concurrency.Cancel {
			t.Fatal("TDX wrappers must serialize in the same non-cancelling group")
		}
		if doc.Env["VM"] != "c8s-tdx-${{ github.run_id }}-${{ github.run_attempt }}" || doc.Env["NS"] != "confai-images" {
			t.Fatalf("unexpected resource identity: %v", doc.Env)
		}
		if doc.Permissions["contents"] != "read" || doc.Permissions["actions"] != "read" {
			t.Fatal("missing checkout/artifact/reaper read permissions")
		}
	}
	exactCall, stagedCall := actionCall(t, exact.Jobs["e2e"].Steps), actionCall(t, staged.Jobs["e2e"].Steps)
	if exactCall.With["exact_image"] != "true" {
		t.Fatal("exact wrapper must enable exact lifecycle")
	}
	stagedMode := stagedCall.With["exact_image"]
	if stagedMode == "" {
		stagedMode = action.Inputs["exact_image"].Default.Value
	}
	if stagedMode != "false" {
		t.Fatal("staged wrapper must disable exact lifecycle")
	}
	if stagedCall.With["keep_cvm"] != "${{ inputs.keep_cvm }}" {
		t.Fatal("staged keep_cvm not forwarded")
	}
	if exactCall.With["keep_cvm"] != "" || exactCall.With["c8s_ref"] != "" {
		t.Fatal("exact acceptance must not override cleanup or the paired source")
	}
}

func TestTDXLifecycleDoesNotAcquireWorkflowSource(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	if action.Runs.Using != "composite" {
		t.Fatal("shared lifecycle must be composite")
	}
	keep := action.Inputs["keep_cvm"].Default
	if keep.Tag != "!!str" || keep.Value != "false" {
		t.Fatal("composite keep_cvm must default to string false")
	}
	foundCleanup := false
	for _, step := range action.Runs.Steps {
		if step.Run != "" && step.Shell != "bash" {
			t.Errorf("%s must declare shell bash", step.Name)
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") || strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			t.Errorf("%s acquires source/evidence inside the shared lifecycle", step.Name)
		}
		// Main ancestry and workflow checkout belong to the wrapper. The
		// lifecycle must reuse that verified source in exact-image mode.
		for _, sourceOperation := range []string{"git merge-base", "refs/remotes/origin/main", "needs.source.outputs"} {
			if strings.Contains(step.Run, sourceOperation) {
				t.Errorf("%s resolves workflow source in shared action", step.Name)
			}
		}
		if step.Name == "teardown" {
			foundCleanup = true
			if strings.Join(strings.Fields(step.If), " ") != "always() && inputs.keep_cvm != 'true'" {
				t.Fatal("cleanup must always run after failures unless the string input is exactly true")
			}
		}
	}
	if !foundCleanup {
		t.Fatal("missing teardown")
	}
}

func TestTDXExactEvidenceAcquisition(t *testing.T) {
	exact, staged := readWorkflow(t, exactWorkflow), readWorkflow(t, stagedWorkflow)
	source := exact.Jobs["source"]
	if source.Outputs["artifact"] != "${{ steps.artifact.outputs.name }}" {
		t.Fatal("the evidence name must come from the source job's artifact lookup")
	}
	lookup := slices.IndexFunc(source.Steps, func(s workflowStep) bool { return s.ID == "artifact" })
	if lookup < 0 || !strings.Contains(source.Steps[lookup].Run, `"repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/artifacts"`) {
		t.Fatal("the evidence lookup must list only this run's artifacts")
	}
	checkout, download, validate, lifecycle := -1, -1, -1, -1
	for i, step := range exact.Jobs["e2e"].Steps {
		switch {
		case strings.HasPrefix(step.Uses, "actions/checkout@"):
			checkout = i
			if step.With["ref"] != "${{ needs.source.outputs.sha }}" || step.With["persist-credentials"] != "false" {
				t.Fatal("exact checkout must consume only verified source without persisting credentials")
			}
		case strings.HasPrefix(step.Uses, "actions/download-artifact@"):
			download = i
			if !reflect.DeepEqual(step.With, map[string]string{
				"name": "${{ needs.source.outputs.artifact }}", "path": "${{ runner.temp }}/tdx-image-acceptance",
			}) {
				t.Fatalf("artifact acquisition must stay in this run without repository/run-id/token fallback: %v", step.With)
			}
		case strings.Contains(step.Run, "tdx-image-acceptance.sh validate"):
			validate = i
			if step.Env["SOURCE_SHA"] != "${{ github.event.workflow_run.head_sha }}" || !strings.Contains(step.Run, `"$GITHUB_RUN_ID"`) {
				t.Fatal("evidence validation must bind source and current run")
			}
		case step.Uses == lifecycleAction:
			lifecycle = i
		}
	}
	if checkout < 0 || download <= checkout || validate <= download || lifecycle <= validate {
		t.Fatal("exact lifecycle must follow verified checkout, same-run download and evidence validation")
	}
	checkouts := 0
	for _, step := range staged.Jobs["e2e"].Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			t.Fatal("staged wrapper must not acquire exact acceptance evidence")
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			checkouts++
			if step.With["ref"] != "${{ github.sha }}" {
				t.Fatal("staged checkout must use the workflow revision, not event-source input")
			}
		}
	}
	if checkouts != 1 {
		t.Fatalf("expected one staged checkout, got %d", checkouts)
	}
}
