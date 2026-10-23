package secrets

import (
	"net/http"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestSecretReleaseRequiresAllowlistedHostMounts(t *testing.T) {
	otherSourceDigest, err := allowlist.HostSourceDigest("/other")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func([]allowlist.ObservedMount) []allowlist.ObservedMount
		allow  bool
	}{
		{"driver and writable socket", func(m []allowlist.ObservedMount) []allowlist.ObservedMount { return m }, true},
		{"missing evidence", func([]allowlist.ObservedMount) []allowlist.ObservedMount { return nil }, false},
		{"missing socket", func(m []allowlist.ObservedMount) []allowlist.ObservedMount { return m[:1] }, false},
		{"extra host mount", func(m []allowlist.ObservedMount) []allowlist.ObservedMount {
			return append(m, allowlist.ObservedMount{Destination: "/etc/config", Class: allowlist.MountHost})
		}, false},
		{"duplicate mount", func(m []allowlist.ObservedMount) []allowlist.ObservedMount { return append(m, m[0]) }, false},
		{"changed source", func(m []allowlist.ObservedMount) []allowlist.ObservedMount {
			m[0].HostSourceDigest = otherSourceDigest
			return m
		}, false},
		{"changed destination", func(m []allowlist.ObservedMount) []allowlist.ObservedMount { m[0].Destination = "/other"; return m }, false},
		{"writable driver", func(m []allowlist.ObservedMount) []allowlist.ObservedMount { m[0].ReadOnly = false; return m }, false},
		{"unknown kind", func(m []allowlist.ObservedMount) []allowlist.ObservedMount { m[0].Class = "unknown"; return m }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			rules := []allowlist.MountRule{
				{Destination: "/usr/lib/libcuda.so", Kind: allowlist.MountHost, Source: "/usr/lib/libcuda.so", ReadOnly: true},
				{Destination: "/run/nvidia-persistenced/socket", Kind: allowlist.MountHost, Source: "/run/nvidia-persistenced/socket"},
			}
			al := hn.h.Policy.(fakePolicy).al
			al.Workloads["api"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: rules}
			mounts := make([]allowlist.ObservedMount, 0, len(rules))
			for _, rule := range rules {
				digest, err := allowlist.HostSourceDigest(rule.Source)
				if err != nil {
					t.Fatal(err)
				}
				mounts = append(mounts, allowlist.ObservedMount{Destination: rule.Destination, Class: allowlist.MountHost, HostSourceDigest: digest, ReadOnly: rule.ReadOnly})
			}
			for i := range hn.inv.containers {
				hn.inv.containers[i].Mounts = []allowlist.ObservedMount{}
			}
			hn.inv.containers[0].Mounts = tc.change(mounts)
			hn.inv.preserveMissingMountEvidence = true
			stored := []byte("model-volume-key")
			hn.seed(t, "/api/db", stored)
			w := do(hn.h, hn.request(t, http.MethodGet, "/api/db"))
			if tc.allow {
				if w.Code != http.StatusOK {
					t.Fatalf("release status=%d body=%s", w.Code, w.Body)
				}
				return
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("release status=%d, want forbidden", w.Code)
			}
			assertNoRelease(t, w, stored)
		})
	}
}

func TestSecretReleaseRequiresNodeRootFileProvenance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		provenance string
		readOnly   bool
		allow      bool
	}{
		{"measured root", allowlist.ProvenanceNodeRoot, true, true},
		{"missing provenance", "", true, false},
		{"other provenance", "dm-verity", true, false},
		{"writable file", allowlist.ProvenanceNodeRoot, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			const source = "/usr/lib/libcuda.so"
			digest, err := allowlist.HostSourceDigest(source)
			if err != nil {
				t.Fatal(err)
			}
			al := hn.h.Policy.(fakePolicy).al
			al.Workloads["api"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{
				{Destination: source, Kind: allowlist.MountNodeRootFile, Source: source, ReadOnly: true},
			}}
			for i := range hn.inv.containers {
				hn.inv.containers[i].Mounts = []allowlist.ObservedMount{}
			}
			hn.inv.containers[0].Mounts = []allowlist.ObservedMount{{
				Destination: source, Class: allowlist.MountHost, HostSourceDigest: digest,
				ReadOnly: tc.readOnly, Provenance: tc.provenance,
			}}
			stored := []byte("model-volume-key")
			hn.seed(t, "/api/db", stored)
			w := do(hn.h, hn.request(t, http.MethodGet, "/api/db"))
			if tc.allow {
				if w.Code != http.StatusOK {
					t.Fatalf("release status=%d body=%s", w.Code, w.Body)
				}
				return
			}
			if w.Code != http.StatusForbidden {
				t.Fatalf("release status=%d, want forbidden", w.Code)
			}
			assertNoRelease(t, w, stored)
		})
	}
}
