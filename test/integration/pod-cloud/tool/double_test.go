package main

// The test binary doubles for docker, kind, go, git and timeout when run.sh
// invokes them through PATH symlinks: the live-lane shell driver is exercised
// against local process doubles only.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var scenarioAssertions = map[string][]string{
	"connected": {"attestedReadiness", "cdsAccessControl", "cleanup", "exactDigests", "meshDNSInternet",
		"negativeProbes", "normalScheduler", "providerDeletion", "readinessCycle", "restartRecovery", "timedRenewal"},
	"verification-timeout": {"attestedReadiness", "cdsAccessControl", "cleanup", "exactDigests", "lateVerifiedResultRejected",
		"normalScheduler", "persistedVerificationDeadline", "providerDeletion", "readinessWithdrawn", "restartRecovery", "timeoutTermination"},
	"warm-assignment": {"assignmentBeforePOST", "attestedReadiness", "cdsAccessControl", "certificateIdentity", "cleanup",
		"conflictingAssignmentRejected", "exactDigests", "genericIdle", "normalScheduler", "poolDrain", "providerDeletion", "restartRecovery", "uidFencedClaim"},
	"cds-outage": {"attestedReadiness", "authenticatedPolicyUpdate", "cdsAccessControl", "cdsIngressRestored",
		"certificateIdentity", "cleanup", "exactDigests", "guestObservedOutage", "normalScheduler", "providerDeletion", "revocationEnforced", "servedPolicyRetained"},
	"cds-renewal-outage": {"attestedReadiness", "authenticatedPolicyUpdate", "cdsAccessControl", "cdsIngressRestored",
		"certificateIdentity", "cleanup", "exactDigests", "guestObservedOutage", "normalScheduler", "providerDeletion",
		"renewalAfterOutage", "revocationEnforced", "servedPolicyRetained", "taskContinuity"},
	"cds-decree": {"attestedReadiness", "cdsAccessControl", "certificateIdentity", "cleanup", "exactDigests", "genesisApplied",
		"localGenericTrustPreserved", "normalScheduler", "pinDecreeApplied", "policyRefusals", "providerDeletion", "staticPinFloor", "taskContinuity", "unjoinedRefusal"},
}

const providerSource = "1111111111111111111111111111111111111111"

type doubleExit int

// double runs one process double and returns its exit status.
func double(tool string, args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			if exit, ok := r.(doubleExit); ok {
				code = int(exit)
				return
			}
			fmt.Fprintln(os.Stderr, r)
			code = 1
		}
	}()
	root := os.Getenv("PODCLOUD_DOUBLE_ROOT")
	node := filepath.Join(root, "node.json")
	call, _ := json.Marshal(append([]string{tool}, args...))
	appendFile(filepath.Join(root, "calls.jsonl"), append(call, '\n'))
	option := func(name string) string {
		for i, a := range args {
			if a == name && i+1 < len(args) {
				return args[i+1]
			}
		}
		panic("missing option " + name)
	}
	switch tool {
	case "timeout":
		path, err := exec.LookPath(args[1])
		must(err)
		must(syscall.Exec(path, args[1:], os.Environ()))
	case "git":
		switch strings.Join(args, " ") {
		case "rev-parse --verify HEAD":
			fmt.Println(providerSource)
		case "status --porcelain=v1 --untracked-files=normal":
			if os.Getenv("PODCLOUD_DIRTY") == "1" {
				fmt.Println(" M internal/podprovider/provider.go")
			}
		default:
			panic("unexpected git command")
		}
	case "go":
		runner := option("-o")
		if args[len(args)-1] == "./test/integration/pod-cloud/tool" {
			data, err := os.ReadFile(os.Getenv("PODCLOUD_TOOL"))
			must(err)
			must(os.WriteFile(runner, data, 0o700))
		} else {
			must(os.WriteFile(runner, []byte("offline runner double"), 0o700))
		}
		must(os.Chmod(runner, 0o700))
	case "kind":
		switch strings.Join(args[:2], " ") {
		case "get clusters":
		case "create cluster":
			var config struct {
				Nodes []struct {
					ExtraMounts []struct{ HostPath string } `json:"extraMounts"`
				}
			}
			readJSON(option("--config"), &config)
			state := config.Nodes[0].ExtraMounts[0].HostPath
			saveJSON(node, []map[string]any{{
				"Id": strings.Repeat("a", 64), "Image": "sha256:" + strings.Repeat("b", 64),
				"Created": time.Now().UTC().Format("2006-01-02T15:04:05") + ".123456Z",
				"Config": map[string]any{"Image": option("--image"), "Labels": map[string]string{
					"io.x-k8s.kind.cluster": option("--name"), "io.x-k8s.kind.role": "control-plane"}},
				"Mounts": []map[string]any{{"Type": "bind", "Source": state, "Destination": "/podcloud", "RW": true}},
			}})
			must(os.WriteFile(option("--kubeconfig"), []byte("private fixture kubeconfig"), 0o600))
			if os.Getenv("PODCLOUD_SCENARIO") == "partial" {
				return 9
			}
		case "delete cluster":
			must(os.Remove(node))
		default:
			panic("unexpected kind command")
		}
	case "docker":
		return dockerDouble(root, node, args)
	default:
		panic("unexpected tool")
	}
	return 0
}

func dockerDouble(root, node string, args []string) int {
	var nodes []map[string]any
	switch args[0] {
	case "version":
		fmt.Println("amd64")
	case "inspect":
		data, err := os.ReadFile(node)
		if err != nil {
			return 1
		}
		os.Stdout.Write(data)
	case "ps":
		if _, err := os.Stat(node); err == nil {
			readJSON(node, &nodes)
			fmt.Println(nodes[0]["Id"])
		}
	case "exec":
		readJSON(node, &nodes)
		state := nodes[0]["Mounts"].([]any)[0].(map[string]any)["Source"].(string)
		scenario := os.Getenv("PODCLOUD_SCENARIO")
		if scenario == "" {
			scenario = "pass"
		}
		if index(args, "/bin/sh") >= 0 {
			// Execute the actual mount probe against the daemon's simulated
			// filesystem view, which may differ despite matching inspect data.
			visible := state
			switch scenario {
			case "empty-mount", "wrong-mount", "wrong-runner":
				visible = filepath.Join(root, filepath.Base(state)+"-daemon-view")
				must(os.Mkdir(visible, 0o700))
				if scenario != "empty-mount" {
					copyFile(filepath.Join(state, "provider.test"), filepath.Join(visible, "provider.test"))
					copyFile(filepath.Join(state, ".mount-nonce"), filepath.Join(visible, ".mount-nonce"))
					if scenario == "wrong-mount" {
						must(os.WriteFile(filepath.Join(visible, ".mount-nonce"), []byte("another invocation\n"), 0o600))
					} else {
						must(os.WriteFile(filepath.Join(visible, "provider.test"), []byte("different runner"), 0o700))
					}
				}
			}
			script := strings.ReplaceAll(args[index(args, "-ec")+1], "/podcloud/", visible+"/")
			cmd := exec.Command("/bin/sh", "-ec", script)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			// Keep the displayed checksum filename in its container namespace.
			os.Stdout.Write(bytes.ReplaceAll(stdout.Bytes(), []byte(visible), []byte("/podcloud")))
			os.Stderr.Write(stderr.Bytes())
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			must(err)
			return 0
		}
		if index(args, "^TestPodProviderCloudLocalCleanup$") >= 0 {
			if scenario == "orphan-busy" {
				return 8
			}
			saveJSON(filepath.Join(state, "closed-before-ledger.json"), map[string]any{"localCleanup": true})
			return 0
		}
		if scenario == "orphan" {
			return 9
		}
		if scenario == "blocked" {
			must(os.WriteFile(filepath.Join(root, "exec-paused"), nil, 0o600))
			until := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(root, "release-exec")); err == nil {
					break
				}
				if time.Now().After(until) {
					return 10
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		var cfg map[string]any
		readJSON(filepath.Join(state, "config.json"), &cfg)
		saveJSON(filepath.Join(state, "ledger.json"), map[string]any{"complete": true, "run": "owned-invocation",
			"owned": map[string]any{"cds": map[string]any{"launchFileSHA256": strings.Repeat("e", 64)}}})
		if scenario == "missing" {
			return 0
		}
		result := map[string]any{}
		for _, k := range []string{"source", "image", "cdsImage", "cliSHA256", "manifestDigest", "diskDigest", "cdsManifestDigest", "cdsDiskDigest", "meshImage"} {
			result[k] = cfg[k]
		}
		requested, _ := cfg["scenario"].(string)
		if requested == "" {
			requested = "connected"
		}
		assertions := scenarioAssertions[requested]
		allTrue := func(names []string) map[string]any {
			m := map[string]any{}
			for _, n := range names {
				m[n] = true
			}
			return m
		}
		runner, err := os.ReadFile(filepath.Join(state, "provider.test"))
		must(err)
		result["version"] = 2
		result["podLaunchFormat"] = "c8s-launch/v2"
		result["cdsLaunchFormat"] = "c8s-cds/v1"
		result["cdsConfigSHA256"] = strings.Repeat("e", 64)
		result["passed"] = true
		result["run"] = "owned-invocation"
		result["scenario"] = requested
		result["providerBinarySHA256"] = sha256Hex(runner)
		result["assertions"] = allTrue(assertions)
		other := "verification-timeout"
		if requested != "connected" {
			other = "connected"
		}
		switch scenario {
		case "wrong-scenario":
			result["scenario"] = other
			result["assertions"] = allTrue(scenarioAssertions[other])
		case "wrong-assertions":
			result["assertions"] = allTrue(scenarioAssertions[other])
		case "missing-scenario":
			delete(result, "scenario")
		case "missing-proof":
			delete(result["assertions"].(map[string]any), assertions[len(assertions)-1])
		case "false-proof":
			result["assertions"].(map[string]any)[assertions[len(assertions)-1]] = false
		case "extra-proof":
			result["assertions"].(map[string]any)["unrequested"] = true
		case "wrong-binary":
			result["providerBinarySHA256"] = strings.Repeat("f", 64)
		case "missing-binary":
			delete(result, "providerBinarySHA256")
		case "changed-binary":
			must(os.WriteFile(filepath.Join(state, "provider.test"), []byte("replacement after execution"), 0o700))
		case "wrong-build":
			var build map[string]any
			readJSON(filepath.Join(state, "provider-build.json"), &build)
			build["providerBinarySHA256"] = strings.Repeat("f", 64)
			saveJSON(filepath.Join(state, "provider-build.json"), build)
		case "stale":
			result["run"] = "different-invocation"
		case "cleanup-only":
			result["assertions"] = map[string]any{"cleanup": true}
		case "wrong-source":
			result["source"] = strings.Repeat("f", 40)
		case "wrong-cds-manifest":
			result["cdsManifestDigest"] = "different"
		case "wrong-cds-disk":
			result["cdsDiskDigest"] = "different"
		case "wrong-cds-config":
			result["cdsConfigSHA256"] = "different"
		case "wrong-launch-format":
			result["cdsLaunchFormat"] = "different"
		}
		saveJSON(filepath.Join(state, "result.json"), result)
	default:
		panic("unexpected Docker command: " + args[0])
	}
	return 0
}

func index(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func readJSON(path string, v any) {
	data, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(data, v))
}

func saveJSON(path string, v any) {
	data, err := json.Marshal(v)
	must(err)
	must(os.WriteFile(path, data, 0o600))
}

func appendFile(path string, data []byte) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	must(err)
	defer f.Close()
	_, err = f.Write(data)
	must(err)
}

func copyFile(from, to string) {
	data, err := os.ReadFile(from)
	must(err)
	info, err := os.Stat(from)
	must(err)
	must(os.WriteFile(to, data, info.Mode().Perm()))
}
