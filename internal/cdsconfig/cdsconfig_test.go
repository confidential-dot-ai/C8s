package cdsconfig

import "testing"

const testWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"c8s-router":{"containers":[{"digest":"sha256:` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `"}]}}}`

func TestMergeWorkloadsKeepsComponentEntries(t *testing.T) {
	const tenant = `{"schema":"c8s.allowlist/v1","workloads":{"tenant-app":{"containers":[{"digest":"sha256:` +
		"2222222222222222222222222222222222222222222222222222222222222222" + `"}]}}}`
	merged, err := MergeWorkloads([]byte(testWorkloads), []byte(tenant))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := merged.Workloads["c8s-router"]; !ok {
		t.Fatalf("merged lost the component entries: %v", merged.Workloads)
	}
	if _, ok := merged.Workloads["tenant-app"]; !ok {
		t.Fatalf("merged lost the tenant entries: %v", merged.Workloads)
	}
	if _, err := MergeWorkloads([]byte(testWorkloads), []byte(testWorkloads)); err == nil {
		t.Fatal("a tenant document replaced a component entry")
	}
	if _, err := MergeWorkloads([]byte(testWorkloads), []byte{}); err == nil {
		t.Fatal("an empty tenant document parsed as no tenant workloads")
	}
}
