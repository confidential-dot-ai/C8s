package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode"
)

// The runtime diagnostic boots the pinned development image as a server and
// two Pod guests, reads their status and attestation without the exact gate,
// and drives each Pod's root serial console through expect to project a
// fixed, read-only set of records: unit states, the journal of the pod
// role's units, sandboxes, containers and containerd plugins. Raw console
// output stays private; only validated records reach evidence. Never
// production acceptance.

const (
	wrapper       = "bypassed-by-60-dev-runc.toml"
	maxTranscript = 262144
	sensitivePat  = `private.?key|-----BEGIN|secret|password|passwd|token|authorization|bearer|credential|kubeconfig|launch\.yaml|\benv(?:ironment|s)?\b|config\s*[=:]`
)

// terminalControl matches complete CSI and OSC sequences only; a printable
// prefix or a partial sequence is never erased.
var terminalControl = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b\r\n]*(?:\x07|\x1b\\)`)

var units = []string{"rke2-role.service", "nri-node-ip.service", "containerd-data-disk.service", "podcvm-containerd.service", "podcvm-kubelet.service", "podcvm-status.service"}

// Journal records matching sensitive are omitted entirely, never partially exposed.
var sensitive = regexp.MustCompile("(?i)" + sensitivePat)

var hexMarker = regexp.MustCompile(`^[0-9a-f]{32}$`)

var journalProjection = func() string {
	pattern, _ := json.Marshal(sensitivePat)
	return `select((.MESSAGE|tostring|test(` + string(pattern) + `;"i"))|not) | ` +
		`{kind:"journal",unit:._SYSTEMD_UNIT,time:.__REALTIME_TIMESTAMP,message:(.MESSAGE|tostring|.[0:1536])}`
}()

const expectScript = `log_user 1
set timeout 30
spawn virtctl --kubeconfig $env(C8S_DIAG_KUBECONFIG) -n $env(C8S_DIAG_NS) console $env(C8S_DIAG_VM)
expect {
    -re {Successfully connected} {}
    timeout {exit 11}
    eof {exit 12}
}
send -- "\r"
expect {
    -re {# ?$} {}
    timeout {exit 13}
    eof {exit 14}
}
send -- "$env(C8S_DIAG_COMMAND)\r"
set timeout 90
expect {
    -re "\r*\n$env(C8S_DIAG_END)\r*\n" {}
    timeout {exit 15}
    eof {exit 16}
}
send -- "\x1d"
exit 0
`

var safeFailures = map[string]bool{"missing scoped VMI console authority": true, "malformed console authorization response": true, "missing native runner credentials": true,
	"owned diagnostic VMI is not running": true, "diagnostic VMI replaced during console": true,
	"console timed out": true, "console output exceeded byte limit": true, "console frame missing or duplicated": true,
	"console frame order differs": true, "console command receipts incomplete": true, "phase deadline reached": true,
	"VMI owner differs": true, "VMI replaced during acceptance": true, "resource ownership differs": true, "resource UID changed": true,
	"production root import failed": true, "production root import timed out": true, "TDX capacity binder did not schedule": true,
	"three owned TDX VMIs did not reach Running": true, "owned Pod runtime capture incomplete": true}

var safeFailurePattern = regexp.MustCompile(`^(console driver exit -?[0-9]+|command failed: kubectl \(exit -?[0-9]+\))$`)

// publicFailure maps an error to the lane's static failure vocabulary; any
// other text is private.
func publicFailure(err error) map[string]string {
	message := err.Error()
	if !safeFailures[message] && !safeFailurePattern.MatchString(message) {
		message = "details withheld; inspect private runner state"
	}
	return map[string]string{"errorClass": errorClass(err), "error": message}
}

func validateDiagnosticPins(p pins) error {
	if err := validatePinStructure(p); err != nil {
		return err
	}
	diagnostic, _ := p.flag("diagnosticOnly")
	development, _ := p.flag("developmentProfile")
	if !diagnostic || !development {
		return errors.New("runtime diagnostics require explicit development-only pins")
	}
	return require(p.str("runtimeWrapper") == wrapper, "development wrapper bypass must be declared")
}

// shellWord encodes one POSIX shell argument without interpreting its contents.
func shellWord(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// consolePayload is the fixed, read-only projection one console session
// runs between two marker lines. No inspect, environment, launch or key
// reads.
func consolePayload(marker string) (string, error) {
	if !hexMarker.MatchString(marker) {
		return "", errors.New("invalid console frame")
	}
	var journalUnits []string
	for _, unit := range units {
		journalUnits = append(journalUnits, "-u "+unit)
	}
	crictl := "timeout 15 /usr/lib/c8s/pod-runtime/bin/crictl --runtime-endpoint unix:///run/k3s/containerd/containerd.sock"
	return "export HISTFILE=/dev/null\nset +e\nset -o pipefail\n" +
		"printf '\\n__C8S_%s_BEGIN__\\n' '" + marker + "'\n" +
		"timeout 10 systemctl show --no-pager -p Id -p LoadState -p ActiveState -p SubState -p Result -p ExecMainCode -p ExecMainStatus " + strings.Join(units, " ") + " 2>/dev/null | jq -McRs '{kind:\"units\",text:.}'\n" +
		"printf '{\"kind\":\"command\",\"name\":\"units\",\"exit\":%s}\\n' \"$?\"\n" +
		"timeout 15 journalctl -b --no-pager -o json -n 160 " + strings.Join(journalUnits, " ") + " 2>/dev/null | jq -Mc " + shellWord(journalProjection) + "\n" +
		"printf '{\"kind\":\"command\",\"name\":\"journal\",\"exit\":%s}\\n' \"$?\"\n" +
		crictl + " pods -o json 2>/dev/null | jq -Mc '.items[]?|{kind:\"sandbox\",id:.id,name:.metadata.name,state:.state,createdAt:.createdAt}'\n" +
		"printf '{\"kind\":\"command\",\"name\":\"sandboxes\",\"exit\":%s}\\n' \"$?\"\n" +
		crictl + " ps -a -o json 2>/dev/null | jq -Mc '.containers[]?|{kind:\"container\",id:.id,name:.metadata.name,state:.state,imageRef:.imageRef,createdAt:.createdAt}'\n" +
		"printf '{\"kind\":\"command\",\"name\":\"containers\",\"exit\":%s}\\n' \"$?\"\n" +
		"timeout 10 /usr/lib/c8s/pod-runtime/bin/ctr --address /run/k3s/containerd/containerd.sock plugins ls 2>/dev/null | head -70 | jq -McRs '{kind:\"plugins\",text:.}'\n" +
		"printf '{\"kind\":\"command\",\"name\":\"plugins\",\"exit\":%s}\\n' \"$?\"\n" +
		"printf '__C8S_%s_END__\\n' '" + marker + "'\n", nil
}

var recordFields = map[string][]string{"units": {"kind", "text"}, "journal": {"kind", "unit", "time", "message"},
	"sandbox": {"kind", "id", "name", "state", "createdAt"}, "container": {"kind", "id", "name", "state", "imageRef", "createdAt"},
	"plugins": {"kind", "text"}, "command": {"kind", "name", "exit"}}

func sameKeys(record map[string]any, fields []string) bool {
	if len(record) != len(fields) {
		return false
	}
	for _, f := range fields {
		if _, ok := record[f]; !ok {
			return false
		}
	}
	return true
}

// consoleLines strips complete terminal control sequences, never printable
// prefixes or partial sequences, and splits the transcript into lines.
func consoleLines(raw []byte) ([]string, error) {
	if len(raw) > maxTranscript {
		return nil, errors.New("oversized console transcript")
	}
	text := terminalControl.ReplaceAllString(strings.ToValidUTF8(string(raw), "\uFFFD"), "")
	return splitLines(strings.ReplaceAll(text, "\r", "")), nil
}

func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

func count(lines []string, s string) int {
	n := 0
	for _, line := range lines {
		if line == s {
			n++
		}
	}
	return n
}

// frameDiagnostics describes a transcript's framing in counts only; it never
// publishes an unparsed line, tail, marker value or terminal payload.
func frameDiagnostics(raw []byte, marker string) (map[string]int, error) {
	lines, err := consoleLines(raw)
	if err != nil {
		return nil, err
	}
	text := strings.ToValidUTF8(string(raw), "\uFFFD")
	original := splitLines(strings.ReplaceAll(text, "\r", ""))
	start, end := "__C8S_"+marker+"_BEGIN__", "__C8S_"+marker+"_END__"
	objects := 0
	for _, line := range lines {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil && record != nil {
			objects++
		}
	}
	return map[string]int{"bytes": len(raw), "lines": len(lines), "controlSequences": len(terminalControl.FindAllStringIndex(text, -1)),
		"rawBeginLines": count(original, start), "rawEndLines": count(original, end),
		"beginLines": count(lines, start), "endLines": count(lines, end),
		"beginOccurrences": strings.Count(text, start), "endOccurrences": strings.Count(text, end),
		"beginIndex": slices.Index(lines, start), "endIndex": slices.Index(lines, end), "jsonObjects": objects}, nil
}

// publicRecords extracts the validated records between the session's
// markers; everything else in the transcript is private.
func publicRecords(raw []byte, marker string) (map[string]any, error) {
	lines, err := consoleLines(raw)
	if err != nil {
		return nil, err
	}
	start, end := "__C8S_"+marker+"_BEGIN__", "__C8S_"+marker+"_END__"
	if count(lines, start) != 1 || count(lines, end) != 1 {
		return nil, errors.New("console frame missing or duplicated")
	}
	a, b := slices.Index(lines, start), slices.Index(lines, end)
	if a >= b {
		return nil, errors.New("console frame order differs")
	}
	records, omitted := []map[string]any{}, 0
	completed := map[string]bool{}
	for _, line := range lines[a+1 : b] {
		var record map[string]any
		// Interleaved boot logs, shell prompts and command echoes are not evidence.
		if err := json.Unmarshal([]byte(line), &record); err != nil || record == nil {
			omitted++
			continue
		}
		kind, _ := record["kind"].(string)
		fields, known := recordFields[kind]
		if !known || !sameKeys(record, fields) {
			omitted++
			continue
		}
		if unit, _ := record["unit"].(string); kind == "journal" && !contains(units, unit) {
			omitted++
			continue
		}
		scalar := true
		for _, value := range record {
			switch v := value.(type) {
			case nil, string:
			case float64:
				scalar = scalar && v == math.Trunc(v)
			default:
				scalar = false
			}
		}
		if !scalar {
			omitted++
			continue
		}
		encoded, _ := json.Marshal(record)
		if len(encoded) > 16384 || sensitive.Match(encoded) {
			omitted++
			continue
		}
		records = append(records, record)
		if kind == "command" {
			if exit, ok := record["exit"].(float64); ok {
				name, _ := record["name"].(string)
				completed[name] = true
				_ = exit
			}
		}
	}
	for _, name := range []string{"units", "journal", "sandboxes", "containers", "plugins"} {
		if !completed[name] {
			return nil, errors.New("console command receipts incomplete")
		}
	}
	if len(completed) != 5 {
		return nil, errors.New("console command receipts incomplete")
	}
	return map[string]any{"records": records, "omittedRecords": omitted}, nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

var boundedProcess = runBounded

// runBounded reads a PTY driver's output with byte and time limits and
// terminates only its own process group. The second result is the lane's
// public reason when the session did not complete.
func runBounded(argv, env []string, deadline time.Time) ([]byte, string) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, "could not start console driver"
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = writer, writer
	ownSession(cmd)
	if err := cmd.Start(); err != nil {
		writer.Close()
		reader.Close()
		return nil, "could not start console driver"
	}
	writer.Close()
	chunks := make(chan []byte)
	go func() {
		defer close(chunks)
		for {
			block := make([]byte, 8192)
			n, err := reader.Read(block)
			if n > 0 {
				chunks <- block[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	exited := false
	var waitErr error
	// awaitExit reports whether the driver has exited within d.
	awaitExit := func(d time.Duration) bool {
		if !exited {
			select {
			case waitErr = <-waited:
				exited = true
			case <-time.After(d):
			}
		}
		return exited
	}
	var raw []byte
	reason := ""
	for reason == "" {
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			reason = "console timed out"
			break
		}
		select {
		case chunk, ok := <-chunks:
			if !ok {
				switch {
				case !awaitExit(5*time.Second) || cmd.ProcessState == nil:
					reason = "console driver exit -1"
				case cmd.ProcessState.ExitCode() != 0:
					reason = fmt.Sprintf("console driver exit %d", cmd.ProcessState.ExitCode())
				case waitErr != nil:
					reason = "console driver wait failed"
				default:
					reason = "ok"
				}
				continue
			}
			raw = append(raw, chunk...)
			if len(raw) > maxTranscript {
				raw = raw[:maxTranscript]
				reason = "console output exceeded byte limit"
			}
		case <-time.After(min(remaining, time.Second)):
		}
	}
	// expect may exit before virtctl; terminate the whole owned session even then.
	killGroup(cmd.Process.Pid, syscall.SIGTERM)
	if !awaitExit(3 * time.Second) {
		killGroup(cmd.Process.Pid, syscall.SIGKILL)
		awaitExit(3 * time.Second)
	}
	reader.Close()
	if reason == "ok" {
		return raw, ""
	}
	return raw, reason
}

type runtimeDiagnostic struct {
	*acceptance
	consoleFn  func(side string) (map[string]any, error)
	diagnoseFn func() error
}

func newRuntimeDiagnostic(root, run, attempt, repo string, pinData []byte) (*runtimeDiagnostic, error) {
	a, err := newAcceptanceWith(root, run, attempt, repo, "c8s-poddebug", "pod-runtime-diagnostic", pinData, 53*time.Minute)
	if err != nil {
		return nil, err
	}
	r := &runtimeDiagnostic{acceptance: a}
	r.validateImage = r.validateDevelopmentImage
	r.prepareFn, r.captureFn, r.vmFn = r.prepare, r.capture, r.vm
	r.consoleFn, r.diagnoseFn = r.console, r.diagnose
	return r, nil
}

// vm reserves the diagnostic guest's vCPUs on the launcher; production
// acceptance keeps its request shape.
func (r *runtimeDiagnostic) vm(side string) map[string]any {
	spec := r.acceptance.vm(side)
	domain := spec["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["domain"].(map[string]any)
	domain["resources"].(map[string]any)["requests"].(map[string]string)["cpu"] = fmt.Sprint(domain["cpu"].(map[string]any)["cores"])
	return spec
}

func (r *runtimeDiagnostic) validateDevelopmentImage(raw []byte) error {
	if err := validateDiagnosticPins(r.pins); err != nil {
		return err
	}
	if raw == nil {
		return nil
	}
	_, err := validateManifestStructure(raw, r.pins)
	return err
}

func (r *runtimeDiagnostic) scope() map[string]any {
	return map[string]any{"diagnosticOnly": true, "productionAcceptance": false, "developmentProfile": true,
		"runtimeWrapper": wrapper, "limitation": "The development image bypasses c8s-runc; a successful boot does not establish production boot or acceptance."}
}

func withScope(scope map[string]any, fields map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range scope {
		out[k] = v
	}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// strictPrintable keeps printable runes only; detail fields never carry
// control characters or line breaks.
func strictPrintable(s string, limit int) string {
	var b []rune
	for _, r := range s {
		if unicode.IsPrint(r) {
			b = append(b, r)
		}
	}
	if len(b) > limit {
		b = b[:limit]
	}
	return string(b)
}

// checkConsoleAuthority asks the API server whether the runner may open the
// VMI console subresource and fails closed; the subresources group has no
// base resource, so kubectl's discovery is bypassed with a raw review.
func (r *runtimeDiagnostic) checkConsoleAuthority() error {
	attributes := map[string]string{"namespace": namespace, "verb": "get", "group": "subresources.kubevirt.io",
		"resource": "virtualmachineinstances", "subresource": "console"}
	review, _ := json.Marshal(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
		"spec": map[string]any{"resourceAttributes": attributes}})
	body, err := kube([]string{"create", "--raw", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "-f", "-"}, review, 30*time.Second)
	if err != nil {
		return err
	}
	var response struct {
		Status map[string]any `json:"status"`
	}
	malformed := errors.New("malformed console authorization response")
	if err := json.Unmarshal(body, &response); err != nil || response.Status == nil {
		return malformed
	}
	allowed, ok := response.Status["allowed"].(bool)
	if !ok {
		return malformed
	}
	denied := false
	if v, present := response.Status["denied"]; present {
		if denied, ok = v.(bool); !ok {
			return malformed
		}
	}
	decision := map[string]any{"attributes": attributes, "allowed": allowed, "denied": denied}
	for _, field := range []string{"reason", "evaluationError"} {
		detail := ""
		if v, present := response.Status[field]; present {
			if detail, ok = v.(string); !ok {
				return malformed
			}
		}
		if sensitive.MatchString(detail) {
			detail = "sensitive detail omitted"
		} else {
			detail = strictPrintable(detail, 1024)
		}
		decision[field] = detail
	}
	if err := write(filepath.Join(r.evidence, "console-authority.json"), decision); err != nil {
		return err
	}
	return require(allowed && !denied, "missing scoped VMI console authority")
}

func (r *runtimeDiagnostic) prepare() error {
	if err := r.validateImage(nil); err != nil {
		return err
	}
	if err := r.checkConsoleAuthority(); err != nil {
		return err
	}
	// tokenFile avoids copying or exposing the in-cluster service-account token.
	serviceAccount := "/var/run/secrets/kubernetes.io/serviceaccount"
	for _, name := range []string{"ca.crt", "token"} {
		if info, err := os.Stat(filepath.Join(serviceAccount, name)); err != nil || !info.Mode().IsRegular() {
			return errors.New("missing native runner credentials")
		}
	}
	kubeconfig := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "owned",
		"clusters": []map[string]any{{"name": "native", "cluster": map[string]string{"server": "https://kubernetes.default.svc", "certificate-authority": filepath.Join(serviceAccount, "ca.crt")}}},
		"users":    []map[string]any{{"name": "runner", "user": map[string]string{"tokenFile": filepath.Join(serviceAccount, "token")}}},
		"contexts": []map[string]any{{"name": "owned", "context": map[string]string{"cluster": "native", "user": "runner", "namespace": namespace}}}}
	if err := write(filepath.Join(r.private, "console-kubeconfig.json"), kubeconfig); err != nil {
		return err
	}
	if err := write(filepath.Join(r.private, "console.exp"), []byte(expectScript)); err != nil {
		return err
	}
	if err := r.acceptance.prepare(); err != nil {
		return err
	}
	return write(filepath.Join(r.evidence, "diagnostic-scope.json"), r.scope())
}

// console runs the fixed projection on one Pod's root serial console and
// publishes only its validated records; the raw transcript stays private.
func (r *runtimeDiagnostic) console(side string) (map[string]any, error) {
	if side != "a" && side != "b" {
		return nil, errors.New("only owned Pod consoles are observable")
	}
	deadline := r.deadline(165 * time.Second)
	before, err := r.instanceFn(side, deadline)
	if err != nil {
		return nil, err
	}
	if before == nil || before.Status.Phase != "Running" {
		return nil, errors.New("owned diagnostic VMI is not running")
	}
	uid := before.Metadata.UID
	marker := newNonce()
	payload, err := consolePayload(marker)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	commandLine := "printf '%s' '" + encoded + "' | base64 -d | /bin/bash"
	if len(commandLine) >= 3500 {
		return nil, errors.New("console command exceeds canonical PTY budget")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "TERM=dumb", "C8S_DIAG_NS=" + namespace, "C8S_DIAG_VM=" + r.name + "-" + side,
		"C8S_DIAG_KUBECONFIG=" + filepath.Join(r.private, "console-kubeconfig.json"), "C8S_DIAG_COMMAND=" + commandLine,
		"C8S_DIAG_END=__C8S_" + marker + "_END__"}
	limit := now().Add(140 * time.Second)
	if early := deadline.Add(-15 * time.Second); early.Before(limit) {
		limit = early
	}
	raw, reason := boundedProcess([]string{"expect", filepath.Join(r.private, "console.exp")}, env, limit)
	if err := write(filepath.Join(r.private, side+"-console.raw"), raw); err != nil {
		return nil, err
	}
	// Revalidate the persisted VM UID and held VMI UID before publishing any observation.
	after, err := r.instanceFn(side, deadline)
	if err != nil {
		return nil, err
	}
	if after == nil || after.Metadata.UID != uid {
		return nil, errors.New("diagnostic VMI replaced during console")
	}
	var driverError any
	if reason != "" {
		driverError = reason
	}
	frame, err := frameDiagnostics(raw, marker)
	if err != nil {
		return nil, err
	}
	if err := write(filepath.Join(r.evidence, side+"-console-status.json"), withScope(r.scope(), map[string]any{"vmiUID": uid, "driverError": driverError, "frame": frame})); err != nil {
		return nil, err
	}
	if reason != "" {
		return nil, errors.New(reason)
	}
	records, err := publicRecords(raw, marker)
	if err != nil {
		return nil, err
	}
	report := withScope(r.scope(), map[string]any{"vmiUID": uid})
	for k, v := range records {
		report[k] = v
	}
	return report, write(filepath.Join(r.evidence, side+"-runtime.json"), report)
}

// diagnose reads status and attestation without the exact gate, then
// captures each Pod's console projection; a failure on one Pod never skips
// the other.
func (r *runtimeDiagnostic) diagnose() error {
	for _, side := range sides {
		port := 8443
		if side == "server" {
			port = 30808
		}
		if err := r.connectFn(side, port); err != nil {
			return err
		}
	}
	deadline := r.deadline(300 * time.Second)
	for range 9 {
		if !now().Before(deadline) {
			break
		}
		// An attested status still describes this dev image; it is not a production receipt.
		if err := r.caFn(filepath.Join(r.evidence, "mesh-ca.pem"), deadline); err != nil {
			if err := r.observationError("cds-ca", "server", err); err != nil {
				return err
			}
		}
		for _, side := range []string{"a", "b"} {
			for _, read := range []struct {
				mode  []string
				label string
				phase string
			}{{[]string{"pod-status", "get"}, "status", "pod-status"}, {[]string{"pod-attest"}, "attestation", "pod-attest-observed"}} {
				report, err := r.cliReadFn(side, read.mode, deadline, false)
				if err == nil {
					err = write(filepath.Join(r.evidence, side+"-diagnostic-"+read.label+".json"), withScope(r.scope(), map[string]any{"report": report}))
				}
				if err != nil {
					if err := r.observationError(read.phase, side, err); err != nil {
						return err
					}
				}
			}
		}
		pause(deadline, 20*time.Second)
	}
	failures := map[string]map[string]string{}
	for _, side := range []string{"a", "b"} {
		progress("guest-runtime", side, "started", nil)
		if _, err := r.consoleFn(side); err != nil {
			failures[side] = publicFailure(err)
			fields := map[string]any{}
			for k, v := range failures[side] {
				fields[k] = v
			}
			progress("guest-runtime", side, "failed", fields)
			continue
		}
		progress("guest-runtime", side, "complete", nil)
	}
	if err := write(filepath.Join(r.evidence, "result.json"), withScope(r.scope(), map[string]any{"captureComplete": len(failures) == 0, "consoleFailures": failures})); err != nil {
		return err
	}
	return require(len(failures) == 0, "owned Pod runtime capture incomplete")
}

// capture records native VM and VMI status only; raw dev serial output
// stays private.
func (r *runtimeDiagnostic) capture() error {
	deadline := now().Add(60 * time.Second)
	for _, side := range sides {
		if _, intended, _ := r.entry("vm", "-"+side); !intended {
			continue
		}
		err := func() error {
			vm, err := r.get("vm", "-"+side, deadline)
			if err != nil {
				return err
			}
			vmi, err := r.instanceFn(side, deadline)
			if err != nil {
				return err
			}
			status := func(obj *object) json.RawMessage {
				var doc struct {
					Status json.RawMessage `json:"status"`
				}
				if obj == nil || json.Unmarshal(obj.raw, &doc) != nil || doc.Status == nil {
					return json.RawMessage("{}")
				}
				return doc.Status
			}
			record := withScope(r.scope(), map[string]any{"vmUID": vm.Metadata.UID, "vmStatus": status(vm), "vmiStatus": status(vmi)})
			var vmiUID any
			if vmi != nil {
				vmiUID = vmi.Metadata.UID
			}
			record["vmiUID"] = vmiUID
			encoded, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if len(encoded) > 32768 {
				return errors.New("oversized diagnostic VM status")
			}
			return write(filepath.Join(r.evidence, side+"-native-status.json"), record)
		}()
		if err != nil {
			if err := write(filepath.Join(r.evidence, side+"-capture-error.json"), publicFailure(err)); err != nil {
				return err
			}
		}
	}
	return nil
}

func runRuntimeDiagnostic(task *runtimeDiagnostic) error {
	entries, err := task.resources()
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("runtime diagnostic already owns resources")
	}
	err = runPhases(task.acceptance, [][2]any{{"prepare", task.prepareFn}, {"provision", task.provisionFn}, {"diagnose", task.diagnoseFn}},
		func(phase string, err error) error {
			return write(filepath.Join(task.evidence, "failure.json"), withScope(task.scope(), withScope(map[string]any{"phase": phase}, anyMap(publicFailure(err)))))
		})
	if err != nil {
		return errors.New("development runtime diagnostic failed; see bounded evidence")
	}
	return nil
}

func anyMap(m map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func runRuntime(mode string) error {
	task, err := newRuntimeDiagnostic(filepath.Join(os.Getenv("RUNNER_TEMP"), "pod-runtime-diagnostic"),
		os.Getenv("GITHUB_RUN_ID"), os.Getenv("GITHUB_RUN_ATTEMPT"), os.Getenv("GITHUB_REPOSITORY"), developmentPins)
	if err != nil {
		return err
	}
	if mode == "cleanup" {
		return task.cleanup()
	}
	if err := runRuntimeDiagnostic(task); err != nil {
		return err
	}
	fmt.Fprintln(progressOut, "Development runtime diagnostics captured; production acceptance remains unverified.")
	return nil
}
