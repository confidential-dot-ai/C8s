package cdsha

import (
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func mkWorkload(t *testing.T) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}
