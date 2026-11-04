package allowlist

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const hostPortsDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

// pinnedContainer is the pinned launch an entry publishing a host port needs.
const pinnedContainer = `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"}}`

func hostPortsEntry(hostPorts string) string {
	return fmt.Sprintf(`{"containers":[`+pinnedContainer+`]%s}`, hostPortsDigest, hostPorts)
}

func hostPortsDocument(hostPorts string) []byte {
	return []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":` + hostPortsEntry(hostPorts) + `}}`)
}

func TestHostPortsAreCanonicalAndOmittedWhenEmpty(t *testing.T) {
	al, err := ParseJSON(hostPortsDocument(`,"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443},{"protocol":"UDP","hostPort":53,"containerPort":5353},{"protocol":"TCP","hostPort":53,"containerPort":5353}]`))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := al.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `"hostPorts":[{"protocol":"TCP","hostPort":53,"containerPort":5353},{"protocol":"UDP","hostPort":53,"containerPort":5353},{"protocol":"TCP","hostPort":443,"containerPort":8443}]`
	if !strings.Contains(string(canonical), want) {
		t.Fatalf("canonical = %s, want it to carry %s", canonical, want)
	}

	for _, hostPorts := range []string{``, `,"hostPorts":[]`} {
		al, err := ParseJSON(hostPortsDocument(hostPorts))
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := al.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(canonical), "hostPorts") {
			t.Fatalf("canonical = %s, want no hostPorts key", canonical)
		}
	}
}

// A write is refused unless every mapping is complete, in range, not the node's
// own, and declared once.
func TestHostPortsRefuseWhatAMappingCannotExpress(t *testing.T) {
	// What does not decode is one empty mapping, whatever made it undecodable.
	const notAMapping = "hostPorts is not a list of {protocol, hostPort, containerPort} mappings"
	type refusal struct{ hostPorts, want string }
	cases := map[string]refusal{
		"unknown protocol":         {`[{"protocol":"ICMP","hostPort":443,"containerPort":8443}]`, `protocol "ICMP" is not TCP, UDP or SCTP`},
		"lower-case protocol":      {`[{"protocol":"tcp","hostPort":443,"containerPort":8443}]`, `protocol "tcp" is not TCP, UDP or SCTP`},
		"no protocol":              {`[{"hostPort":443,"containerPort":8443}]`, `protocol "" is not TCP, UDP or SCTP`},
		"no host port":             {`[{"protocol":"TCP","containerPort":8443}]`, "host port 0 is not between 1 and 65535"},
		"host port zero":           {`[{"protocol":"TCP","hostPort":0,"containerPort":8443}]`, "host port 0 is not between 1 and 65535"},
		"no container port":        {`[{"protocol":"TCP","hostPort":443}]`, "container port 0 is not between 1 and 65535"},
		"container port zero":      {`[{"protocol":"TCP","hostPort":443,"containerPort":0}]`, "container port 0 is not between 1 and 65535"},
		"host port too large":      {`[{"protocol":"TCP","hostPort":65536,"containerPort":8443}]`, "host port 65536 is not between 1 and 65535"},
		"container port too large": {`[{"protocol":"TCP","hostPort":443,"containerPort":70000}]`, "container port 70000 is not between 1 and 65535"},
		"negative port":            {`[{"protocol":"TCP","hostPort":-1,"containerPort":8443}]`, "host port -1 is not between 1 and 65535"},
		"string port":              {`[{"protocol":"TCP","hostPort":"443","containerPort":8443}]`, notAMapping},
		"declared twice":           {`[{"protocol":"TCP","hostPort":443,"containerPort":8443},{"protocol":"TCP","hostPort":443,"containerPort":8444}]`, "TCP host port 443 is declared twice"},
		"unknown member":           {`[{"protocol":"TCP","hostPort":443,"containerPort":8443,"nodePort":30443}]`, notAMapping},
		"not a list":               {`{"protocol":"TCP","hostPort":443,"containerPort":8443}`, notAMapping},
		"null mapping":             {`[null]`, notAMapping},
	}
	for _, port := range nodeServicePorts {
		cases[fmt.Sprintf("node serves %d", port)] = refusal{
			fmt.Sprintf(`[{"protocol":"TCP","hostPort":%d,"containerPort":8443}]`, port),
			fmt.Sprintf("host port %d is one the node answers on its own address", port),
		}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseJSON(hostPortsDocument(`,"hostPorts":` + tc.hostPorts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseJSON = %v, want it to name %q", err, tc.want)
			}
			if _, err := ParseWorkloadJSON([]byte(hostPortsEntry(`,"hostPorts":` + tc.hostPorts))); err == nil {
				t.Fatalf("ParseWorkloadJSON accepted hostPorts %s", tc.hostPorts)
			}
		})
	}
}

// A served document keeps the entry and the rest of its policy; only its
// published ports are dropped.
func TestServedHostPortsItCannotValidateAreDropped(t *testing.T) {
	for name, hostPorts := range map[string]string{
		"unknown protocol": `[{"protocol":"ICMP","hostPort":443,"containerPort":8443}]`,
		"port too large":   `[{"protocol":"TCP","hostPort":70000,"containerPort":8443}]`,
		"string port":      `[{"protocol":"TCP","hostPort":"443","containerPort":8443}]`,
		"not a list":       `{"protocol":"TCP","hostPort":443,"containerPort":8443}`,
		"unknown member":   `[{"protocol":"TCP","hostPort":443,"containerPort":8443,"nodePort":30443}]`,
		"node serves it":   `[{"protocol":"TCP","hostPort":6443,"containerPort":8443}]`,
		"one bad mapping":  `[{"protocol":"TCP","hostPort":443,"containerPort":8443},{"protocol":"TCP","hostPort":80,"containerPort":"8080"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			al, err := ParseServedJSON(hostPortsDocument(`,"hostPorts":` + hostPorts))
			if err != nil {
				t.Fatalf("ParseServedJSON = %v, want the document kept", err)
			}
			w, ok := al.Workloads["w"]
			if !ok {
				t.Fatal("the entry was dropped, want only its host ports dropped")
			}
			if w.HostPorts != nil {
				t.Fatalf("hostPorts = %v, want them dropped", w.HostPorts)
			}
		})
	}
}

// A strict parse refuses unpinned published ports; a served one drops them.
func TestHostPortsRequireAPinnedLaunch(t *testing.T) {
	hostPorts := `,"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443}]`
	for name, containers := range map[string]string{
		"command any":    `{"digest":%q,"command":{"policy":"any"},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"deny"}}`,
		"args any":       `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"any"},"mounts":{"policy":"deny"},"env":{"policy":"deny"}}`,
		"mounts any":     `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"any"},"env":{"policy":"deny"}}`,
		"env any":        `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"},"env":{"policy":"any"}}`,
		"no env policy":  `{"digest":%q,"command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"mounts":{"policy":"deny"}}`,
		"init container": pinnedContainer + `],"initContainers":[{"digest":%[1]q,"command":{"policy":"any"},"args":{"policy":"any"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			entry := fmt.Sprintf(`{"containers":[`+containers+`]`+hostPorts+`}`, hostPortsDigest)
			doc := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":` + entry + `}}`)
			if _, err := ParseJSON(doc); err == nil || !strings.Contains(err.Error(), "declared host ports need every container to pin its launch") {
				t.Fatalf("ParseJSON = %v, want a pin refusal", err)
			}
			if _, err := ParseWorkloadJSON([]byte(entry)); err == nil {
				t.Fatal("ParseWorkloadJSON accepted an unpinned entry publishing a host port")
			}
			served, err := ParseServedJSON(doc)
			if err != nil {
				t.Fatal(err)
			}
			if w := served.Workloads["w"]; w.HostPorts != nil {
				t.Fatalf("served hostPorts = %v, want them dropped", w.HostPorts)
			}
		})
	}
}

// The front door's shape: a pinned container publishing one port on two protocols.
func TestHostPortsAcceptAPinnedLaunchWithHostMounts(t *testing.T) {
	container := fmt.Sprintf(`{"digest":%q,"command":{"policy":"exact","argv":["/nginx"]},"args":{"policy":"deny"},"mounts":{"policy":"exact","rules":[{"destination":"/etc/nginx","kind":"host","source":"/usr/lib/c8s/router-nginx","readOnly":true}]},"env":{"policy":"match","variables":{"HOSTNAME":{"present":true}}}}`, hostPortsDigest)
	entry := `{"containers":[` + container + `],"hostPorts":[{"protocol":"TCP","hostPort":443,"containerPort":8443},{"protocol":"UDP","hostPort":443,"containerPort":8443}]}`
	w, err := ParseWorkloadJSON([]byte(entry))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.HostPorts) != 2 {
		t.Fatalf("hostPorts = %v, want both mappings kept", w.HostPorts)
	}
}

// grantingEntry is one pinned declaration publishing the mappings its pod maps.
func grantingEntry(t *testing.T, argv []string, mappings ...HostPort) Workload {
	t.Helper()
	return Workload{
		Containers: []Container{{
			Digest:  dig(t, hostPortsDigest),
			Command: ArgvPolicy{Policy: PolicyExact, Argv: argv},
			Args:    ArgvPolicy{Policy: PolicyDeny},
			Mounts:  MountPolicy{Policy: PolicyDeny},
			Env:     EnvPolicy{Policy: PolicyDeny},
		}},
		HostPorts: mappings,
	}
}

// One entry must declare every mapping and admit the launch.
func TestGrantsHostPorts(t *testing.T) {
	https := HostPort{Protocol: "TCP", HostPort: 443, ContainerPort: 8443}
	http := HostPort{Protocol: "TCP", HostPort: 80, ContainerPort: 8080}
	argv := []string{"/nginx"}
	index := func(entries ...Workload) *Index {
		workloads := map[string]Workload{}
		for n, w := range entries {
			workloads["w"+strconv.Itoa(n)] = w
		}
		return (&Allowlist{Workloads: workloads}).BuildIndex()
	}
	open := grantingEntry(t, argv)
	open.Containers[0].Command = ArgvPolicy{Policy: PolicyAny}
	for _, tc := range []struct {
		name     string
		index    *Index
		mappings []HostPort
		want     bool
	}{
		{"the entry declares the mapping", index(grantingEntry(t, argv, https)), []HostPort{https}, true},
		{"the entry declares both mappings", index(grantingEntry(t, argv, https, http)), []HostPort{https, http}, true},
		{"the entry declares one of two", index(grantingEntry(t, argv, https)), []HostPort{https, http}, false},
		{"another container port", index(grantingEntry(t, argv, https)), []HostPort{{Protocol: "TCP", HostPort: 443, ContainerPort: 9000}}, false},
		{"another protocol", index(grantingEntry(t, argv, https)), []HostPort{{Protocol: "UDP", HostPort: 443, ContainerPort: 8443}}, false},
		{"the entry refuses the argv", index(grantingEntry(t, []string{"/other"}, https)), []HostPort{https}, false},
		{"another entry admits the launch", index(grantingEntry(t, []string{"/other"}, https), open), []HostPort{https}, false},
		{"no entry declares it", index(open), []HostPort{https}, false},
		{"no mapping to grant", index(grantingEntry(t, argv, https)), nil, false},
		{"no allowlist", nil, []HostPort{https}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, err := ObserveEnv(nil)
			if err != nil {
				t.Fatal(err)
			}
			r := RunningContainer{Digest: hostPortsDigest, Argv: argv, Mounts: []ObservedMount{}, Env: env}
			if got := tc.index.GrantsHostPorts(r, tc.mappings); got != tc.want {
				t.Fatalf("GrantsHostPorts(%s) = %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}

// A sandbox is held to what some entry declares; no launch is known yet.
func TestDeclaresHostPorts(t *testing.T) {
	https := HostPort{Protocol: "TCP", HostPort: 443, ContainerPort: 8443}
	argv := []string{"/nginx"}
	for _, tc := range []struct {
		name     string
		entries  []Workload
		mappings []HostPort
		want     bool
	}{
		{"an entry declares it", []Workload{grantingEntry(t, argv, https)}, []HostPort{https}, true},
		{"an entry declares another host port", []Workload{grantingEntry(t, argv, https)}, []HostPort{{Protocol: "TCP", HostPort: 8080, ContainerPort: 8080}}, false},
		{"no mapping to declare", []Workload{grantingEntry(t, argv, https)}, nil, false},
		{"no entry declares any", nil, []HostPort{https}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workloads := map[string]Workload{}
			for n, w := range tc.entries {
				workloads["w"+strconv.Itoa(n)] = w
			}
			index := (&Allowlist{Workloads: workloads}).BuildIndex()
			if got := index.DeclaresHostPorts(tc.mappings); got != tc.want {
				t.Fatalf("DeclaresHostPorts(%s) = %t, want %t", tc.name, got, tc.want)
			}
		})
	}
}
