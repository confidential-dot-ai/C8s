package recoveryfixture

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func baseline() Snapshot {
	h := strings.Repeat("a", 64)
	return Snapshot{KernelBootID: "00000000-0000-0000-0000-000000000001", AssignmentSHA256: h, RequestSHA256: h, ConfigSHA256: h, ManifestSHA256: h, JournalSHA256: h, HistorySHA256: h,
		AssignedUID: "assigned", RuntimeUID: "runtime", CredentialID: "pcvm-" + h,
		Tasks:    map[string]Process{h: {PID: 50, Birth: 50}, strings.Repeat("b", 64): {PID: 51, Birth: 51}, strings.Repeat("c", 64): {PID: 52, Birth: 52}},
		Services: map[string]Process{Units[0]: {PID: 10, Birth: 10}, Units[1]: {PID: 11, Birth: 11}, Units[2]: {PID: 12, Birth: 12}}, NRI: Process{PID: 13, Birth: 13}}
}

func complete(t *testing.T) Receipt {
	t.Helper()
	b := baseline()
	r := Receipt{Schema: 1, Scope: Scope, State: "complete", Baseline: &b}
	before := b
	for _, name := range Phases {
		wire, err := json.Marshal(before)
		if err != nil {
			t.Fatal(err)
		}
		var after Snapshot
		if err := json.Unmarshal(wire, &after); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "status":
			after.Services[Units[0]] = Process{PID: 20, Birth: 20}
		case "kubelet":
			after.Services[Units[1]] = Process{PID: 21, Birth: 21}
		case "runtime":
			after.Services[Units[1]], after.Services[Units[2]], after.NRI = Process{PID: 31, Birth: 31}, Process{PID: 32, Birth: 32}, Process{PID: 33, Birth: 33}
		}
		r.Phases = append(r.Phases, Phase{Name: name, Before: before, After: after})
		before = after
	}
	return r
}

func TestRecoveryRequiresActualSameBootProcessReplacement(t *testing.T) {
	if err := complete(t).ValidateComplete(baseline()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name string
		edit func(*Receipt)
	}{
		{"no restart", func(r *Receipt) { r.Phases[0].After.Services[Units[0]] = r.Phases[0].Before.Services[Units[0]] }},
		{"NRI not replaced", func(r *Receipt) { r.Phases[2].After.NRI = r.Phases[2].Before.NRI }},
		{"guest rebooted", func(r *Receipt) { r.Phases[2].After.KernelBootID = "00000000-0000-0000-0000-000000000002" }},
		{"assignment changed", func(r *Receipt) { r.Phases[1].After.RequestSHA256 = strings.Repeat("b", 64) }},
		{"history or policy lost", func(r *Receipt) { r.Phases[2].After.HistorySHA256 = strings.Repeat("b", 64) }},
		{"PID reused by another task", func(r *Receipt) { r.Phases[2].After.Tasks[strings.Repeat("a", 64)] = Process{PID: 50, Birth: 99} }},
		{"checker task changed", func(r *Receipt) { r.Phases[2].After.Tasks[strings.Repeat("c", 64)] = Process{PID: 53, Birth: 53} }},
		{"checker task missing", func(r *Receipt) { delete(r.Phases[2].After.Tasks, strings.Repeat("c", 64)) }},
		{"failed phase", func(r *Receipt) { r.FailedPhase = &r.Phases[2] }},
		{"partial sequence", func(r *Receipt) { r.Phases = r.Phases[:2] }},
		{"unobserved baseline", func(r *Receipt) { r.Baseline = nil }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := complete(t)
			change.edit(&r)
			if r.ValidateComplete(baseline()) == nil {
				t.Fatal("accepted incomplete or changed recovery")
			}
		})
	}
}

func TestReceiptRefusesAmbiguousOrUnboundedWire(t *testing.T) {
	raw, err := json.Marshal(complete(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(raw, []byte(" {}")...), []byte(strings.Repeat("x", MaxReceipt+1)), []byte(`{"schema":1,"scope":"wrong","state":"complete"}`), []byte(`{"schema":1,"unknown":true}`)} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("accepted invalid receipt")
		}
	}
}

func TestFixtureFinalizePreservesOnlyExpectedEnablement(t *testing.T) {
	for _, kind := range []string{"absent", "relative", "absolute", "wrong-link", "file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			link := filepath.Join(root, "etc/systemd/system/multi-user.target.wants/pod-recovery-fixture.service")
			if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
				t.Fatal(err)
			}
			target := ""
			switch kind {
			case "relative":
				target = "../pod-recovery-fixture.service"
			case "absolute":
				target = "/etc/systemd/system/pod-recovery-fixture.service"
			case "wrong-link":
				target = "../another.service"
			case "file":
				if err := os.WriteFile(link, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(link, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if target != "" {
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			accept := kind == "absent" || kind == "relative" || kind == "absolute"
			for range 2 {
				cmd := exec.CommandContext(t.Context(), "bash", "profile/mkosi.finalize")
				cmd.Env = append(os.Environ(), "BUILDROOT="+root)
				output, err := cmd.CombinedOutput()
				if (err == nil) != accept {
					t.Fatalf("accept=%v: %v: %s", accept, err, output)
				}
			}
			switch kind {
			case "file":
				data, err := os.ReadFile(link)
				if err != nil || string(data) != "preserve" {
					t.Fatal("conflicting file changed")
				}
			case "directory":
				entries, err := os.ReadDir(link)
				if err != nil || len(entries) != 0 {
					t.Fatal("conflicting directory changed")
				}
			default:
				if target == "" {
					target = "../pod-recovery-fixture.service"
				}
				actual, err := os.Readlink(link)
				if err != nil || actual != target {
					t.Fatal("enablement target changed")
				}
			}
		})
	}
}
