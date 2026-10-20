package cdsattest

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/routing"
)

func TestTunnelBudget(t *testing.T) {
	limit := func(content string) string {
		path := filepath.Join(t.TempDir(), "memory.max")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name      string
		flag      string
		limitFile string
		want      int64
	}{
		{"flag wins", "1Gi", limit("8589934592\n"), 1 << 30},
		{"75% of the limit", "", limit("8589934592\n"), 6 << 30},
		{"no limit", "", limit("max\n"), routing.DefaultTunnelBudget},
		{"no cgroup file", "", filepath.Join(t.TempDir(), "absent"), routing.DefaultTunnelBudget},
		{"small limit covers one request", "", limit("16777216\n"), oneRequestBudget},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var flag quantityFlag
			if tc.flag != "" {
				if err := flag.Set(tc.flag); err != nil {
					t.Fatal(err)
				}
			}
			if got := tunnelBudget(flag, tc.limitFile, slog.New(slog.DiscardHandler)); got != tc.want {
				t.Fatalf("tunnelBudget(%q, %s) = %d, want %d", tc.flag, tc.name, got, tc.want)
			}
		})
	}
}

func TestQuantityFlagRejects(t *testing.T) {
	for _, v := range []string{"", "lots", "0", "-1Gi", "1.5"} {
		var q quantityFlag
		if err := q.Set(v); err == nil {
			t.Errorf("Set(%q) = nil, want an error", v)
		}
	}
}
