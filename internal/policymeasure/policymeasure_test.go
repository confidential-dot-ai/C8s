package policymeasure_test

import (
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/policymeasure"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestSidecarJournal(t *testing.T) {
	if want := filepath.Join(workloadclaims.SidecarSocketDir, policymeasure.JournalName); policymeasure.SidecarJournal != want {
		t.Errorf("SidecarJournal = %q, want %q", policymeasure.SidecarJournal, want)
	}
}
