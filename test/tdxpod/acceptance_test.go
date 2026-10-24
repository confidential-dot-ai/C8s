package main

// Offline gates for the native hardware harness, not hardware substitutes.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func newAcceptanceTask(t *testing.T) *acceptance {
	t.Helper()
	a, err := newAcceptance(t.TempDir(), "123", "2", testRepo)
	if err != nil {
		t.Fatal(err)
	}
	noSleep(t)
	quiet(t)
	return a
}

type call struct {
	argv  []string
	env   []string
	stdin []byte
	limit time.Duration
}

// fakeExecute answers every child process with result and records the calls.
func fakeExecute(t *testing.T, result processResult) *[]call {
	t.Helper()
	var calls []call
	execute = func(argv, env []string, stdin []byte, limit time.Duration) (processResult, error) {
		calls = append(calls, call{argv, env, stdin, limit})
		return result, nil
	}
	t.Cleanup(func() { execute = runProcess })
	return &calls
}

func withPins(t *testing.T, data []byte, changes map[string]any) pins {
	t.Helper()
	p, err := loadPins(data)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range changes {
		p = p.with(k, v)
	}
	return p
}

func TestProductionPinRejectsMixedSourcesAndMutatedManifest(t *testing.T) {
	p := withPins(t, productionPins, nil)
	if err := validatePins(p.with("profileSource", strings.Repeat("0", 40))); err == nil {
		t.Fatal("accepted mixed sources")
	}
	for _, data := range [][]byte{[]byte("{}"), []byte(strings.Repeat("x", 65537))} {
		if _, err := validateManifest(data, p); err == nil {
			t.Fatalf("accepted %d bytes", len(data))
		}
	}
	for _, change := range []string{"valid", "disk", "platform", "rtmr2"} {
		manifest := map[string]any{"build": map[string]any{"platform": "tdx"}, "inputs": map[string]any{"base_image": map[string]any{"sha256": p.str("diskSHA256")}},
			"outputs": map[string]any{"disk_image": map[string]any{"sha256": p.str("diskSHA256")}},
			"tdx": map[string]any{"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("a", 96), "rtmr2": strings.Repeat("a", 96),
				"firmware": map[string]any{"path": "OVMF.tdx.fd", "sha256": strings.Repeat("d", 64)}}}
		switch change {
		case "disk":
			manifest["outputs"].(map[string]any)["disk_image"].(map[string]any)["sha256"] = strings.Repeat("f", 64)
		case "platform":
			manifest["build"].(map[string]any)["platform"] = "snp"
		case "rtmr2":
			manifest["tdx"].(map[string]any)["rtmr2"] = ""
		}
		raw, _ := json.Marshal(manifest)
		_, err := validateManifest(raw, p.with("manifestSHA256", sha256Hex(raw)))
		if (err == nil) != (change == "valid") {
			t.Fatalf("%s: %v", change, err)
		}
	}
}

func TestRotationRequiresNewKeySameInstanceAndNamedIdentity(t *testing.T) {
	initial := leaf{SandboxID: "pcvm-a", Serial: "1", SPKI: "old", Workload: "connected", Denied: true}
	with := func(mutate func(*leaf)) *leaf {
		l := initial
		mutate(&l)
		return &l
	}
	for _, c := range []struct {
		current *leaf
		want    bool
	}{{with(func(l *leaf) { l.Serial = "2" }), false}, {with(func(l *leaf) { l.SPKI = "new" }), false},
		{with(func(l *leaf) { l.Serial, l.SPKI = "2", "new" }), true}} {
		if got, err := renewed(&initial, c.current); err != nil || got != c.want {
			t.Fatalf("renewed(%+v) = %v, %v", c.current, got, err)
		}
	}
	for _, mutate := range []func(*leaf){func(l *leaf) { l.SandboxID = "pcvm-b" }, func(l *leaf) { l.Workload = "" }, func(l *leaf) { l.Denied = false }} {
		if _, err := renewed(&initial, with(mutate)); err == nil {
			t.Fatal("accepted a changed identity")
		}
	}
}

func TestEarlyRotationThatPersistsCannotSatisfyTimedRenewal(t *testing.T) {
	initial := &leaf{SandboxID: "pcvm-a", Serial: "1", SPKI: "first", Workload: "connected", Denied: true, NotBefore: "2026-10-23T10:00:00Z", NotAfter: "2026-10-23T16:00:00Z"}
	early := &leaf{SandboxID: "pcvm-a", Serial: "2", SPKI: "early", Workload: "connected", Denied: true, NotBefore: "2026-10-23T10:01:00Z", NotAfter: "2026-10-23T16:01:00Z"}
	timed := &leaf{SandboxID: "pcvm-a", Serial: "3", SPKI: "timed", Workload: "connected", Denied: true, NotBefore: "2026-10-23T10:55:00Z", NotAfter: "2026-10-23T16:55:00Z"}
	persisted := *timed
	persisted.NotAfter = early.NotAfter
	for _, c := range []struct {
		previous, current *leaf
		elapsed           time.Duration
		want              bool
	}{{initial, early, 60 * time.Second, false}, {initial, early, 3900 * time.Second, false}, {early, early, 3900 * time.Second, false},
		{early, timed, 3300 * time.Second, true}, {early, &persisted, 3300 * time.Second, false}} {
		if got, err := renewalEvent(c.previous, c.current, c.elapsed); err != nil || got != c.want {
			t.Fatalf("renewalEvent(%s, %s, %v) = %v, %v", c.previous.SPKI, c.current.SPKI, c.elapsed, got, err)
		}
	}
}

func TestExpectedMeshNameMatchesRealSourceAndRejectsChangedContract(t *testing.T) {
	if err := validateSourceContract("../.."); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	path := filepath.Join(source, "pkg/workloadclaims/workloadclaims.go")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, declaration := range []string{`const MeshContainerName = "c8s-mesh-endpoint"`, "",
		"const MeshContainerName = \"c8s-mesh\"\nconst MeshContainerName = \"another\""} {
		if err := os.WriteFile(path, []byte(declaration), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateSourceContract(source); err == nil {
			t.Fatalf("accepted %q", declaration)
		}
	}
	if err := os.WriteFile(path, []byte("const MeshContainerName = \"c8s-mesh\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSourceContract(source); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptRequiresCorrectUIDNoRestartAndZeroCheckerExit(t *testing.T) {
	running := map[string]any{"running": map[string]any{"startedAt": "2026-10-23T10:00:00Z"}}
	status := func(mutate func(doc map[string]any)) json.RawMessage {
		doc := map[string]any{"metadata": map[string]any{"uid": "pod"}, "status": map[string]any{
			"initContainerStatuses": []map[string]any{{"name": "c8s-mesh", "ready": true, "restartCount": 0, "state": running}},
			"containerStatuses": []map[string]any{
				{"name": "app", "ready": true, "restartCount": 0, "state": running},
				{"name": "checker", "restartCount": 0, "state": map[string]any{"terminated": map[string]any{"exitCode": 0, "startedAt": "2026-10-23T10:00:00Z"}}}}}}
		if mutate != nil {
			mutate(doc)
		}
		raw, _ := json.Marshal(doc)
		return raw
	}
	state, err := podStateFrom(status(nil), "pod")
	if err != nil || !state.Complete || !state.Ready {
		t.Fatalf("state: %+v, %v", state, err)
	}
	if _, err := podStateFrom(status(nil), "other"); err == nil {
		t.Fatal("accepted another Pod's status")
	}
	inits := func(doc map[string]any) []map[string]any {
		return doc["status"].(map[string]any)["initContainerStatuses"].([]map[string]any)
	}
	containers := func(doc map[string]any) []map[string]any {
		return doc["status"].(map[string]any)["containerStatuses"].([]map[string]any)
	}
	for _, mutate := range []func(map[string]any){
		func(doc map[string]any) { inits(doc)[0]["restartCount"] = 1 },
		func(doc map[string]any) {
			inits(doc)[0]["state"] = map[string]any{"terminated": map[string]any{"exitCode": 0}}
		},
		func(doc map[string]any) { doc["status"].(map[string]any)["initContainerStatuses"] = []map[string]any{} },
		func(doc map[string]any) { containers(doc)[0]["restartCount"] = 1 },
		func(doc map[string]any) {
			containers(doc)[0]["state"] = map[string]any{"terminated": map[string]any{"exitCode": 0}}
		},
		func(doc map[string]any) {
			containers(doc)[1]["state"] = map[string]any{"terminated": map[string]any{"exitCode": 12}}
		}} {
		if _, err := podStateFrom(status(mutate), "pod"); err == nil {
			t.Fatalf("accepted %s", status(mutate))
		}
	}
}

func TestReadinessCycleRejectsExtraOutages(t *testing.T) {
	for _, trace := range [][]bool{{false, false, true, true, false, true}, {true, false, false, true}} {
		if !readinessCycle(trace) {
			t.Errorf("rejected %v", trace)
		}
	}
	for _, trace := range [][]bool{{}, {false, true}, {true, false}, {true, false, true, false, true}} {
		if readinessCycle(trace) {
			t.Errorf("accepted %v", trace)
		}
	}
}

func TestNoForwardAuthorityKeepsTheBoundedDirectWarmup(t *testing.T) {
	a := newAcceptanceTask(t)
	a.identity = &identity{Services: map[string]endpoint{"a": {IP: "10.96.0.1"}}}
	ledger(t, a.owned, resource{Kind: "service", Suffix: "-a", UID: str("owned")})
	service := ownedObject(t, a.owned, "service", "-a", nil)
	kube = func(args []string, _ []byte, _ time.Duration) ([]byte, error) {
		if args[0] == "get" {
			return service, nil
		}
		return nil, errors.New("command failed: kubectl (exit 1)")
	}
	t.Cleanup(func() { kube = runKubectl })
	a.instanceFn = func(string, time.Time) (*object, error) { return nil, nil }
	dial = func(string, string, time.Duration) (net.Conn, error) { return nil, errors.New("booting") }
	t.Cleanup(func() { dial = net.DialTimeout })
	if err := a.connect("a", 8443); err != nil {
		t.Fatal(err)
	}
	if a.connections["a:8443"] != "10.96.0.1:8443" || len(a.forwards) != 0 {
		t.Fatalf("connections: %v, forwards: %d", a.connections, len(a.forwards))
	}
}

func TestAuthenticatedReadsUseRootCLICommandsAndKeepExactGate(t *testing.T) {
	a := newAcceptanceTask(t)
	a.connections["a:8443"] = "127.0.0.1:12345"
	a.identity = &identity{ExpectedDigests: []string{"sha256:" + strings.Repeat("a", 64)}}
	calls := fakeExecute(t, processResult{stdout: []byte("{}")})
	for _, read := range []struct {
		mode  []string
		exact bool
	}{{[]string{"pod-attest"}, true}, {[]string{"pod-status", "get"}, true}, {[]string{"pod-attest"}, false}} {
		if _, err := a.cliRead("a", read.mode, time.Time{}, read.exact); err != nil {
			t.Fatal(err)
		}
	}
	exact, status, observed := (*calls)[0].argv, (*calls)[1].argv, (*calls)[2].argv
	if exact[0] != a.cli || exact[1] != "pod-attest" || status[1] != "pod-status" || status[2] != "get" {
		t.Fatalf("argv: %v %v", exact, status)
	}
	gate := slices.Index(exact, "--expect-digest")
	if slices.Contains(exact, "node") || gate < 0 || slices.Contains(observed, "--expect-digest") || !slices.Equal(exact[:gate], observed) {
		t.Fatalf("exact: %v observed: %v", exact, observed)
	}
	a.identity.ExpectedDigests = nil
	if _, err := a.cliRead("a", []string{"pod-attest"}, time.Time{}, true); err == nil {
		t.Fatal("exact read without a digest gate")
	}
}

func TestReadWrapperRejectsMutationsAndPrivateKeyFlags(t *testing.T) {
	a := newAcceptanceTask(t)
	calls := fakeExecute(t, processResult{})
	for _, c := range []struct {
		phase, side string
		options     []string
	}{{"secrets-put", "server", nil}, {"cds-ca", "server", []string{"--operator-key", "private.key"}},
		{"pod-status", "a", []string{"--insecure", "true"}}, {"pod-attest", "server", nil}} {
		if _, err := a.readOnlyCLI(c.phase, c.side, c.options, time.Time{}); err == nil {
			t.Errorf("accepted %s %s %v", c.phase, c.side, c.options)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestReadErrorsExposeBoundedStderrWithoutArgvStdoutOrPrivatePath(t *testing.T) {
	a := newAcceptanceTask(t)
	output := quiet(t)
	t.Setenv("C8S_OPERATOR_KEY", "not-for-child")
	stderr := strings.Repeat("x", 5000) + a.private + "/manifest.json: digest mismatch\x1b"
	calls := fakeExecute(t, processResult{code: 1, stdout: []byte("not-for-logs"), stderr: []byte(stderr)})
	_, err := a.readOnlyCLI("pod-attest", "a", []string{"--node", "argv-not-for-logs"}, time.Time{})
	if err == nil {
		t.Fatal("read succeeded")
	}
	c := (*calls)[0]
	for _, kv := range c.env {
		if strings.HasPrefix(kv, "C8S_OPERATOR_KEY=") {
			t.Fatal("operator key inherited")
		}
	}
	if c.stdin != nil {
		t.Fatal("stdin passed to a read")
	}
	var record struct {
		Error, Phase, Side, Timestamp string
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(a.evidence, "a-pod-attest-last-error.json"))), &record); err != nil {
		t.Fatal(err)
	}
	if len([]rune(record.Error)) > 4096 || !strings.Contains(record.Error, "digest mismatch") || record.Phase != "pod-attest" || record.Side != "a" || record.Timestamp == "" {
		t.Fatalf("record: %+v", record)
	}
	for _, forbidden := range []string{"argv-not-for-logs", "not-for-logs", a.private, "\x1b"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("output exposes %q", forbidden)
		}
	}
}

func TestReadTimeoutDoesNotStringifyTheCommand(t *testing.T) {
	a := newAcceptanceTask(t)
	output := quiet(t)
	fakeExecute(t, processResult{timedOut: true, code: -1, stdout: []byte("stdout-not-for-logs"), stderr: []byte("context deadline")})
	_, err := a.readOnlyCLI("pod-status", "b", nil, time.Time{})
	wantError(t, err, "context deadline")
	for _, forbidden := range []string{"argv-not-for-logs", "stdout-not-for-logs", a.cli} {
		if strings.Contains(output.String(), forbidden) || strings.Contains(err.Error(), forbidden) {
			t.Fatalf("exposes %q", forbidden)
		}
	}
}

func TestMeshProbeUsesOwnedBinaryKnownModeAndBoundedDiagnostics(t *testing.T) {
	a := newAcceptanceTask(t)
	a.connections["a:8080"] = "127.0.0.1:12345"
	calls := fakeExecute(t, processResult{code: 1, stderr: []byte("peer certificate signature invalid")})
	_, err := a.leaf("a", "certless")
	wantError(t, err, "signature invalid")
	c := (*calls)[0]
	if c.argv[0] != a.probe || c.limit != 15*time.Second || c.stdin != nil {
		t.Fatalf("call: %+v", c)
	}
	if _, err := a.leaf("a", "unknown-mode"); err == nil || len(*calls) != 1 {
		t.Fatalf("unknown mode: %v, calls %d", err, len(*calls))
	}
	var record struct{ Error, Phase, Side string }
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(a.evidence, "a-pod-mesh-last-error.json"))), &record); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.Error, "signature invalid") || record.Phase != "pod-mesh" || record.Side != "a" {
		t.Fatalf("record: %+v", record)
	}
}

func TestWarmupSavesStatusAndDiagnosticAttestationWithoutBypassingGate(t *testing.T) {
	a := newAcceptanceTask(t)
	var calls [][]string
	a.caFn = func(string, time.Time) error { return nil }
	a.cliReadFn = func(side string, mode []string, _ time.Time, exact bool) (json.RawMessage, error) {
		calls = append(calls, append([]string{side}, mode...))
		if side == "a" && slices.Equal(mode, []string{"pod-attest"}) && exact {
			return nil, errors.New("measured digest mismatch")
		}
		return json.RawMessage(`{"side":"` + side + `","measured_digests":["observed"]}`), nil
	}
	podStateOf = func(json.RawMessage, string) (podState, error) { return podState{Ready: true, Running: true}, nil }
	t.Cleanup(func() { podStateOf = podStateFrom })
	a.leafFn = func(string, string) (*leaf, error) { return &leaf{Workload: "connected"}, nil }
	traces, states := map[string][]bool{"a": {}, "b": {}}, map[string]podState{}
	initial, _, err := a.warmupRound(time.Time{}, traces, states)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := initial["b"]; !ok || len(initial) != 1 {
		t.Fatalf("initial: %v", initial)
	}
	if !slices.Equal(calls[0], []string{"a", "pod-status", "get"}) || !slices.Equal(calls[3], []string{"b", "pod-status", "get"}) {
		t.Fatalf("calls: %v", calls)
	}
	if !exists(filepath.Join(a.evidence, "a-initial-status.json")) || exists(filepath.Join(a.evidence, "a-initial-attestation.json")) || !exists(filepath.Join(a.evidence, "b-initial-attestation.json")) {
		t.Fatal("initial evidence differs")
	}
	var diagnostic struct {
		DiagnosticOnly        bool `json:"diagnosticOnly"`
		ExactDigestGatePassed bool `json:"exactDigestGatePassed"`
		Report                struct {
			MeasuredDigests []string `json:"measured_digests"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(a.evidence, "a-diagnostic-attestation.json"))), &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !diagnostic.DiagnosticOnly || diagnostic.ExactDigestGatePassed || !slices.Equal(diagnostic.Report.MeasuredDigests, []string{"observed"}) {
		t.Fatalf("diagnostic: %+v", diagnostic)
	}
}

func TestCDSAndFirstPodFailuresDoNotHideOtherPodObservations(t *testing.T) {
	a := newAcceptanceTask(t)
	var calls [][]string
	a.caFn = func(string, time.Time) error { return errors.New("CDS unavailable") }
	a.cliReadFn = func(side string, mode []string, _ time.Time, _ bool) (json.RawMessage, error) {
		calls = append(calls, append([]string{side}, mode...))
		if side == "a" {
			return nil, errors.New("guest unavailable")
		}
		return json.RawMessage(`{"side":"` + side + `"}`), nil
	}
	podStateOf = func(json.RawMessage, string) (podState, error) { return podState{Running: true}, nil }
	t.Cleanup(func() { podStateOf = podStateFrom })
	initial, _, err := a.warmupRound(time.Time{}, map[string][]bool{"a": {}, "b": {}}, map[string]podState{})
	if err != nil || len(initial) != 0 {
		t.Fatalf("initial: %v, %v", initial, err)
	}
	seen := func(want []string) bool {
		return slices.ContainsFunc(calls, func(c []string) bool { return slices.Equal(c, want) })
	}
	if !seen([]string{"b", "pod-status", "get"}) || !seen([]string{"b", "pod-attest"}) {
		t.Fatalf("calls: %v", calls)
	}
	for _, name := range []string{"server-cds-ca-last-error.json", "a-pod-attest-last-error.json", "b-initial-status.json"} {
		if !exists(filepath.Join(a.evidence, name)) {
			t.Fatalf("%s missing", name)
		}
	}
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files[path] = readFile(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestLaunchSecretsUseOnlyRequiredBundleFilesWithoutDiskCopy(t *testing.T) {
	a := newAcceptanceTask(t)
	expected := map[string]map[string]string{}
	for _, side := range sides {
		role := "pod"
		if side == "server" {
			role = "server"
		}
		dir := filepath.Join(a.bundle, side, role)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		expected[side] = map[string]string{}
		for _, name := range []string{"pubkey", "launch.yaml", "launch.yaml.sig"} {
			expected[side][name] = side + ":" + name + "\n"
			if err := os.WriteFile(filepath.Join(dir, name), []byte(expected[side][name]), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "operator.key"), []byte("fixture excluded from guest inputs"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshot(t, a.root)
	type created struct {
		kind, suffix string
		spec         map[string]any
	}
	var creates []created
	a.createFn = func(kind, suffix string, spec map[string]any) (*object, error) {
		creates = append(creates, created{kind, suffix, spec})
		return &object{}, nil
	}
	if err := a.createLaunchSecrets(); err != nil {
		t.Fatal(err)
	}
	if len(creates) != 3 {
		t.Fatalf("creates: %d", len(creates))
	}
	for i, side := range sides {
		c := creates[i]
		if c.kind != "secret" || c.suffix != "-"+side+"-opkey" || c.spec["kind"] != "Secret" || c.spec["type"] != "Opaque" {
			t.Fatalf("create %d: %+v", i, c)
		}
		data := c.spec["data"].(map[string]string)
		if len(data) != 3 {
			t.Fatalf("secret data: %v", data)
		}
		for name, encoded := range data {
			decoded, _ := base64.StdEncoding.DecodeString(encoded)
			if string(decoded) != expected[side][name] {
				t.Fatalf("%s %s: %q", side, name, decoded)
			}
		}
	}
	after := snapshot(t, a.root)
	if len(after) != len(before) {
		t.Fatalf("files changed: %d -> %d", len(before), len(after))
	}
	for path, content := range before {
		if after[path] != content {
			t.Fatalf("%s changed", path)
		}
	}
}

func TestIncompleteBundleCannotCreateAPartialSecret(t *testing.T) {
	a := newAcceptanceTask(t)
	dir := filepath.Join(a.bundle, "server/server")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pubkey", "launch.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	creates := 0
	a.createFn = func(string, string, map[string]any) (*object, error) { creates++; return &object{}, nil }
	if err := a.createLaunchSecrets(); !errors.Is(err, os.ErrNotExist) || creates != 0 {
		t.Fatalf("err %v, creates %d", err, creates)
	}
}

func TestVMShapesShareReadonlyRootButOnlyServerHasScratch(t *testing.T) {
	a := newAcceptanceTask(t)
	for _, side := range sides {
		got, raw := shapeOf(t, a.vm(side))
		spec := got.Spec.Template.Spec
		if got.Spec.RunStrategy != "Once" || len(spec.Domain.LaunchSecurity) != 1 || !spec.Domain.Devices.Disks[0].Disk.Readonly {
			t.Fatalf("%s: %s", side, raw)
		}
		if _, tdx := spec.Domain.LaunchSecurity["tdx"]; !tdx {
			t.Fatalf("%s launchSecurity: %v", side, spec.Domain.LaunchSecurity)
		}
		if spec.Volumes[0]["persistentVolumeClaim"].(map[string]any)["claimName"] != a.name+"-root" {
			t.Fatalf("%s root: %v", side, spec.Volumes[0])
		}
		scratch := slices.ContainsFunc(spec.Domain.Devices.Disks, func(d struct {
			Serial string `json:"serial"`
			Disk   struct {
				Readonly bool `json:"readonly"`
			} `json:"disk"`
		}) bool {
			return d.Serial == "confai-scratch"
		})
		if scratch != (side == "server") {
			t.Fatalf("%s scratch: %v", side, scratch)
		}
	}
}

func TestPhaseFailuresReachEvidenceRedacted(t *testing.T) {
	a := newAcceptanceTask(t)
	leak := fmt.Errorf("c8s command failed: open %s/bundle/pod/launch.yaml: \x01no such file", a.private)
	a.captureFn = func() error { return errors.New("capture read " + a.private + "/manifest.json") }
	a.stopForwardsFn = func() error { return nil }
	err := runPhases(a, [][2]any{{"prepare", func() error { return leak }}}, a.recordFailure)
	wantError(t, err, "c8s command failed")
	for _, name := range []string{"failure.json", "capture-error.json"} {
		text := readFile(t, filepath.Join(a.evidence, name))
		if strings.Contains(text, a.private) || !strings.Contains(text, "private-run-directory") {
			t.Fatalf("%s leaks the private directory: %s", name, text)
		}
	}
	if text := readFile(t, filepath.Join(a.evidence, "failure.json")); !strings.Contains(text, "?no such file") || !strings.Contains(text, `"type": "errorString"`) {
		t.Fatalf("failure.json: %s", text)
	}
	d := newBootTask(t)
	d.recordFailure(fmt.Errorf("resolved image pins: %s/pins.json", d.private))
	if text := readFile(t, filepath.Join(d.evidence, "failure.json")); strings.Contains(text, d.private) || !strings.Contains(text, "private-run-directory") {
		t.Fatalf("boot failure.json leaks the private directory: %s", text)
	}
}
