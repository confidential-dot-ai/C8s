package main

// Development-console isolation, ownership, confidentiality and bound checks.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const marker = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func transcript(extra ...map[string]any) []byte {
	var lines []string
	for _, record := range extra {
		line, _ := json.Marshal(record)
		lines = append(lines, string(line))
	}
	for _, name := range []string{"units", "journal", "sandboxes", "containers", "plugins"} {
		line, _ := json.Marshal(map[string]any{"kind": "command", "name": name, "exit": 0})
		lines = append(lines, string(line))
	}
	return []byte("unframed private boot data\r\n__C8S_" + marker + "_BEGIN__\r\n" + strings.Join(lines, "\r\n") + "\r\n__C8S_" + marker + "_END__\r\n")
}

func newRuntimeTask(t *testing.T) *runtimeDiagnostic {
	t.Helper()
	r, err := newRuntimeDiagnostic(t.TempDir(), "123", "1", testRepo, developmentPins)
	if err != nil {
		t.Fatal(err)
	}
	noSleep(t)
	quiet(t)
	return r
}

func needTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not installed", name)
	}
}

func TestDevAndProductionPinsAreMutuallyExclusive(t *testing.T) {
	production, development := withPins(t, productionPins, nil), withPins(t, developmentPins, nil)
	if err := validatePins(production); err != nil {
		t.Fatal(err)
	}
	if err := validateDiagnosticPins(development); err != nil {
		t.Fatal(err)
	}
	if validatePins(development) == nil || validateDiagnosticPins(production) == nil {
		t.Fatal("pins crossed profiles")
	}
	for field, value := range map[string]any{"diagnosticOnly": false, "developmentProfile": false, "runtimeWrapper": "enabled", "profileSource": strings.Repeat("f", 40)} {
		if validateDiagnosticPins(development.with(field, value)) == nil {
			t.Errorf("accepted %s=%v", field, value)
		}
	}
	// False flags must not turn the production validator into a dev pin selector.
	if validatePins(production.with("diagnosticOnly", false)) == nil {
		t.Fatal("accepted a development marker in production")
	}
}

func TestConsoleAuthorityUsesExactAttributesAndFailsClosed(t *testing.T) {
	r := newRuntimeTask(t)
	calls, datas := sequence(t, reply{body: []byte(`{"status":{"allowed":true,"reason":"existing scoped role"}}`)})
	if err := r.checkConsoleAuthority(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal((*calls)[0], []string{"create", "--raw", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "-f", "-"}) {
		t.Fatalf("call: %v", (*calls)[0])
	}
	var request struct {
		Spec struct {
			ResourceAttributes map[string]string `json:"resourceAttributes"`
		} `json:"spec"`
	}
	if err := json.Unmarshal((*datas)[0], &request); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"namespace": "confai-images", "verb": "get", "group": "subresources.kubevirt.io", "resource": "virtualmachineinstances", "subresource": "console"}
	if len(request.Spec.ResourceAttributes) != len(want) {
		t.Fatalf("attributes: %v", request.Spec.ResourceAttributes)
	}
	for k, v := range want {
		if request.Spec.ResourceAttributes[k] != v {
			t.Fatalf("attributes: %v", request.Spec.ResourceAttributes)
		}
	}
	for _, status := range []string{`{"allowed":false,"denied":true,"reason":"existing role denies console","evaluationError":"` + strings.Repeat("x", 2000) + `"}`,
		`{"allowed":false,"reason":"token=canary"}`, `{"allowed":true,"denied":true}`, `{}`, `{"allowed":"true"}`, `{"allowed":true,"denied":"false"}`, `null`} {
		sequence(t, reply{body: []byte(`{"status":` + status + `}`)})
		if err := r.checkConsoleAuthority(); err == nil {
			t.Fatalf("accepted %s", status)
		}
		report := readFile(t, filepath.Join(r.evidence, "console-authority.json"))
		var decision struct {
			EvaluationError string `json:"evaluationError"`
		}
		if err := json.Unmarshal([]byte(report), &decision); err != nil || strings.Contains(report, "canary") || len(decision.EvaluationError) > 1024 {
			t.Fatalf("report after %s: %s", status, report)
		}
	}
	sequence(t, reply{err: errors.New("command failed: kubectl (exit 1)")})
	if err := r.checkConsoleAuthority(); err == nil {
		t.Fatal("accepted a failed review")
	}
}

func TestProjectionDropsSecretsNoiseAndUnrequestedFields(t *testing.T) {
	safe := map[string]any{"kind": "journal", "unit": units[1], "time": "1", "message": "NRI denied unapproved image"}
	variant := func(changes map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range safe {
			out[k] = v
		}
		for k, v := range changes {
			out[k] = v
		}
		return out
	}
	result, err := publicRecords(transcript(safe, variant(map[string]any{"message": "Authorization: Bearer canary"}),
		variant(map[string]any{"message": "-----BEGIN PRIVATE KEY-----canary"}), variant(map[string]any{"message": "environment: canary"}),
		variant(map[string]any{"unit": "unrelated.service"}), variant(map[string]any{"env": "canary"}), map[string]any{"kind": "container", "env": "canary"}), marker)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if result["omittedRecords"] != 6 || strings.Contains(string(encoded), "canary") || strings.Contains(string(encoded), "private boot") {
		t.Fatalf("result: %s", encoded)
	}
	records := result["records"].([]map[string]any)
	if len(records) != 6 || records[0]["message"] != safe["message"] {
		t.Fatalf("records: %v", records)
	}
	for _, raw := range [][]byte{[]byte(strings.ReplaceAll(string(transcript()), "_END__", "_BAD__")), append(transcript(), transcript()...), []byte(strings.Repeat("x", maxTranscript+1))} {
		if _, err := publicRecords(raw, marker); err == nil {
			t.Fatalf("accepted %d bytes", len(raw))
		}
	}
}

func TestJournalFiltersLateSecretMarkerBeforeTruncation(t *testing.T) {
	needTool(t, "jq")
	for _, c := range []struct {
		message string
		exposed bool
	}{{"early canary " + strings.Repeat("x", 1700) + " Authorization: Bearer confidential", false}, {"ordinary runtime failure " + strings.Repeat("x", 1700), true}} {
		record, _ := json.Marshal(map[string]string{"_SYSTEMD_UNIT": units[0], "__REALTIME_TIMESTAMP": "1", "MESSAGE": c.message})
		cmd := exec.Command("jq", "-c", journalProjection)
		cmd.Stdin = strings.NewReader(string(record))
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if !c.exposed {
			if len(out) != 0 {
				t.Fatalf("exposed: %s", out)
			}
			continue
		}
		var projected struct{ Message string }
		if err := json.Unmarshal(out, &projected); err != nil || len(projected.Message) != 1536 {
			t.Fatalf("projected: %s (%v)", out, err)
		}
	}
}

func TestPayloadHasFixedReadOnlyProjectionAndValidShell(t *testing.T) {
	needTool(t, "bash")
	payload, err := consolePayload(marker)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v %s", err, out)
	}
	for _, forbidden := range []string{" inspect", "cat /", "kubectl", "/etc/confai", "launch.yaml", "systemctl restart", "printenv"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("payload contains %q", forbidden)
		}
	}
	if !strings.Contains(payload, "--runtime-endpoint unix:///run/k3s/containerd/containerd.sock") || !strings.Contains(payload, "-n 160") || !strings.Contains(payload, "printf '\\n__C8S_%s_BEGIN__") || strings.Contains(payload, "jq -c") {
		t.Fatal("payload lost its fixed projection")
	}
	if len(base64.StdEncoding.EncodeToString([]byte(payload)))+45 >= 3500 {
		t.Fatal("payload exceeds the PTY budget")
	}
	if _, err := consolePayload("; echo arbitrary"); err == nil {
		t.Fatal("accepted an arbitrary marker")
	}
}

func TestStaticFailuresAreUsefulButProcessDetailsStayPrivate(t *testing.T) {
	for _, message := range []string{"console driver exit 13", "missing scoped VMI console authority", "command failed: kubectl (exit 1)"} {
		if got := publicFailure(errors.New(message))["error"]; got != message {
			t.Fatalf("%q became %q", message, got)
		}
	}
	for _, err := range []error{errors.New("private argv canary"), errors.New("command timed out: canary"), os.ErrNotExist} {
		encoded, _ := json.Marshal(publicFailure(err))
		if strings.Contains(string(encoded), "canary") || !strings.Contains(string(encoded), "details withheld") {
			t.Fatalf("failure: %s", encoded)
		}
	}
}

// surrogate installs a shell script under name in a private PATH directory.
func surrogate(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestExpectPTYDeliversPayloadAndReceivesCompleteFrame(t *testing.T) {
	needTool(t, "expect")
	// A local console surrogate exercises expect itself; it never invokes guest commands.
	dir := t.TempDir()
	framed := framedTranscript("\x1b[?2004l\x1b]3008;context=private-canary\x1b\\")
	if err := os.WriteFile(filepath.Join(dir, "frame.bin"), framed, 0o600); err != nil {
		t.Fatal(err)
	}
	surrogate(t, dir, "virtctl", "echo 'Successfully connected'\nread line\nprintf 'root# '\nread line\ncat \"$(dirname \"$0\")/frame.bin\"\ndd bs=1 count=1 2>/dev/null\n")
	script := filepath.Join(dir, "console.exp")
	if err := os.WriteFile(script, []byte(expectScript), 0o600); err != nil {
		t.Fatal(err)
	}
	end := "__C8S_" + marker + "_END__"
	env := []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "TERM=dumb", "C8S_DIAG_KUBECONFIG=/unused", "C8S_DIAG_NS=confai-images",
		"C8S_DIAG_VM=owned", "C8S_DIAG_COMMAND=fixed command", "C8S_DIAG_END=" + end}
	raw, reason := runBounded([]string{"expect", script}, env, time.Now().Add(5*time.Second))
	if reason != "" || !strings.Contains(string(raw), end) {
		t.Fatalf("reason %q, raw %q", reason, raw)
	}
	report, err := publicRecords(raw, marker)
	if err != nil {
		t.Fatalf("%v; raw %q", err, raw)
	}
	if encoded, _ := json.Marshal(report); len(report["records"].([]map[string]any)) != 5 || strings.Contains(string(encoded), "canary") {
		t.Fatalf("report: %s", encoded)
	}
}

func TestConsoleSubprocessIsByteAndTimeBounded(t *testing.T) {
	needTool(t, "sh")
	env := []string{"PATH=" + os.Getenv("PATH")}
	raw, reason := runBounded([]string{"sh", "-c", "head -c 500000 /dev/zero | tr '\\0' x"}, env, time.Now().Add(5*time.Second))
	if len(raw) != maxTranscript || reason != "console output exceeded byte limit" {
		t.Fatalf("len %d, reason %q", len(raw), reason)
	}
	start := time.Now()
	_, reason = runBounded([]string{"sh", "-c", "sleep 5"}, env, start.Add(100*time.Millisecond))
	if reason != "console timed out" || time.Since(start) > 4*time.Second {
		t.Fatalf("reason %q after %v", reason, time.Since(start))
	}
}

func TestConsoleChecksIdentityBeforeAndAfterAndKeepsRawPrivate(t *testing.T) {
	r := newRuntimeTask(t)
	owned := parse(t, []byte(`{"metadata":{"uid":"owned"},"status":{"phase":"Running"}}`))
	replacement := parse(t, []byte(`{"metadata":{"uid":"replacement"},"status":{"phase":"Running"}}`))
	r.instanceFn = func(string, time.Time) (*object, error) { return nil, errors.New("ownership mismatch") }
	boundedProcess = func([]string, []string, time.Time) ([]byte, string) {
		t.Fatal("console driven without ownership")
		return nil, ""
	}
	t.Cleanup(func() { boundedProcess = runBounded })
	if _, err := r.console("a"); err == nil {
		t.Fatal("console opened without ownership")
	}
	newNonce = func() string { return marker }
	t.Cleanup(func() { newNonce = nonce })
	for _, c := range []struct {
		after   *object
		success bool
	}{{replacement, false}, {owned, true}} {
		instances := 0
		r.instanceFn = func(string, time.Time) (*object, error) {
			instances++
			if instances == 1 {
				return owned, nil
			}
			return c.after, nil
		}
		var env []string
		boundedProcess = func(_ []string, e []string, _ time.Time) ([]byte, string) { env = e; return transcript(), "" }
		report, err := r.console("a")
		if c.success {
			if err != nil || report["diagnosticOnly"] != true || report["productionAcceptance"] != false {
				t.Fatalf("report: %v, %v", report, err)
			}
		} else if err == nil || exists(filepath.Join(r.evidence, "a-runtime.json")) {
			t.Fatal("published after a replaced VMI")
		}
		if instances != 2 {
			t.Fatalf("instance reads: %d", instances)
		}
		var names []string
		for _, kv := range env {
			names = append(names, kv[:strings.Index(kv, "=")])
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"C8S_DIAG_COMMAND", "C8S_DIAG_END", "C8S_DIAG_KUBECONFIG", "C8S_DIAG_NS", "C8S_DIAG_VM", "PATH", "TERM"}) {
			t.Fatalf("env: %v", names)
		}
		if !exists(filepath.Join(r.private, "a-console.raw")) || exists(filepath.Join(r.evidence, "a-console.raw")) {
			t.Fatal("raw transcript placement differs")
		}
	}
}

func TestDiagnosticCannotEnterAcceptanceOrPublishRawCaptureEvenOnFailure(t *testing.T) {
	for _, failure := range []error{nil, errors.New("private process argv canary")} {
		r := newRuntimeTask(t)
		stops := 0
		r.prepareFn = func() error { return nil }
		r.provisionFn = func() error { return nil }
		r.diagnoseFn = func() error { return failure }
		r.stopForwardsFn = func() error { stops++; return nil }
		r.observeFn = func() error { t.Fatal("acceptance entered"); return nil }
		err := runRuntimeDiagnostic(r)
		if failure == nil && err != nil {
			t.Fatal(err)
		}
		if failure != nil {
			wantError(t, err, "development runtime diagnostic failed")
		}
		if stops != 1 {
			t.Fatalf("stopForwards calls: %d", stops)
		}
		matches, _ := filepath.Glob(filepath.Join(r.evidence, "*"))
		for _, path := range matches {
			text := readFile(t, path)
			if strings.Contains(text, "canary") || strings.Contains(text, `"passed": true`) {
				t.Fatalf("%s: %s", path, text)
			}
		}
		if failure != nil && !strings.Contains(readFile(t, filepath.Join(r.evidence, "failure.json")), "details withheld") {
			t.Fatal("failure evidence lacks the static vocabulary")
		}
	}
}

func TestConsoleFailureOnADoesNotSkipB(t *testing.T) {
	r := newRuntimeTask(t)
	r.connectFn = func(string, int) error { return nil }
	r.caFn = func(string, time.Time) error { return nil }
	r.cliReadFn = func(string, []string, time.Time, bool) (json.RawMessage, error) { return json.RawMessage("{}"), nil }
	var consoles []string
	r.consoleFn = func(side string) (map[string]any, error) {
		consoles = append(consoles, side)
		if side == "a" {
			return nil, errors.New("private canary")
		}
		return map[string]any{}, nil
	}
	wantError(t, r.diagnose(), "capture incomplete")
	if !slices.Equal(consoles, []string{"a", "b"}) {
		t.Fatalf("consoles: %v", consoles)
	}
	receipt := readFile(t, filepath.Join(r.evidence, "result.json"))
	var result struct {
		CaptureComplete bool `json:"captureComplete"`
	}
	if err := json.Unmarshal([]byte(receipt), &result); err != nil || result.CaptureComplete || strings.Contains(receipt, "canary") {
		t.Fatalf("receipt: %s", receipt)
	}
}

// framedTranscript prefixes the BEGIN marker line with terminal output.
func framedTranscript(prefix string) []byte {
	return []byte(strings.Replace(string(transcript()), "__C8S_"+marker+"_BEGIN__", prefix+"__C8S_"+marker+"_BEGIN__", 1))
}

func TestFrameControlsAreNormalizedWithoutAcceptingPrintablePrefixes(t *testing.T) {
	for _, prefix := range []string{"\x1b[?2004l\r", "\x1b]3008;context=private-canary\x07", "\x1b]3008;context=private-canary\x1b\\", "\x1b[0m\x1b]3008;context=private-canary\x1b\\"} {
		raw := framedTranscript(prefix)
		report, err := publicRecords(raw, marker)
		if err != nil {
			t.Fatalf("%q: %v", prefix, err)
		}
		counts, err := frameDiagnostics(raw, marker)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal([]any{report, counts})
		if len(report["records"].([]map[string]any)) != 5 || counts["rawBeginLines"] != 0 || counts["beginLines"] != 1 || counts["endLines"] != 1 || counts["controlSequences"] == 0 || strings.Contains(string(encoded), "canary") {
			t.Fatalf("%q: %s", prefix, encoded)
		}
	}
	for _, prefix := range []string{"printable-prefix ", "\x1b]3008;unterminated "} {
		if _, err := publicRecords(framedTranscript(prefix), marker); err == nil {
			t.Fatalf("accepted prefix %q", prefix)
		}
	}
	if _, err := publicRecords(append(transcript(), transcript()...), marker); err == nil {
		t.Fatal("accepted a duplicated frame")
	}
	counts, err := frameDiagnostics([]byte(strings.Replace(string(transcript()), "_BEGIN__", "_MISSING__", 1)), marker)
	if err != nil || counts["beginLines"] != 0 || counts["beginIndex"] != -1 || counts["jsonObjects"] != 5 {
		t.Fatalf("counts: %v, %v", counts, err)
	}
}

func TestDiagnosticReservesItsVCPUCountWithoutChangingProductionVM(t *testing.T) {
	r := newRuntimeTask(t)
	production := newAcceptanceTask(t)
	for side, expected := range map[string]string{"server": "4", "a": "2", "b": "2"} {
		requests := func(vm map[string]any) map[string]string {
			return vm["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["domain"].(map[string]any)["resources"].(map[string]any)["requests"].(map[string]string)
		}
		if got := requests(r.vmFn(side))["cpu"]; got != expected {
			t.Fatalf("%s cpu request %q", side, got)
		}
		if _, set := requests(production.vmFn(side))["cpu"]; set {
			t.Fatalf("%s production VM requests cpu", side)
		}
	}
}
