package volumed

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
)

func formatRequest(t *testing.T, rootOwner string) Request {
	t.Helper()
	req := testMutableRequest(t)
	req.Blob.Format = &volume.Format{FS: "ext4", RootOwner: rootOwner}
	return req
}

func TestOpenFormatsOnlyABlankDevice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		blank bool
		want  string
	}{
		{"blank device", true, "CryptOpen,Blank,MakeExt4,MountRW"},
		// A wrong key reads as no filesystem; only blankness formats.
		{"written device", false, "CryptOpen,Blank,MountRW"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := newOps()
			ops.blank = tc.blank
			o := testOpener(t, ops)
			if err := o.Open(t.Context(), formatRequest(t, "65532:65532")); err != nil {
				t.Fatalf("open: %v", err)
			}
			if got := ops.sequence(); got != tc.want {
				t.Fatalf("sequence = %q, want %q", got, tc.want)
			}
			if tc.blank && (len(ops.formatted) != 1 || ops.formatted[0] != "65532:65532") {
				t.Fatalf("formatted with root owner %v", ops.formatted)
			}
		})
	}
}

// A blob without format never probes or formats, as before.
func TestOpenWithoutFormatNeverProbes(t *testing.T) {
	ops := newOps()
	ops.blank = true
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), testMutableRequest(t)); err != nil {
		t.Fatal(err)
	}
	if got := ops.sequence(); got != "CryptOpen,MountRW" {
		t.Fatalf("sequence = %q", got)
	}
}

// A format that fails closes the mapping it formatted through.
func TestOpenUnwindsAFailedFormat(t *testing.T) {
	ops := newOps()
	ops.blank = true
	ops.failOn = "MakeExt4"
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), formatRequest(t, "")); err == nil {
		t.Fatal("open succeeded through a failed format")
	}
	if c, v, m := ops.leaked(); c+v+m != 0 {
		t.Fatalf("leaked crypt=%d verity=%d mounts=%d", c, v, m)
	}
}

// The format is part of what a second caller must reproduce.
func TestReopenWithAnotherFormatIsRefused(t *testing.T) {
	ops := newOps()
	o := testOpener(t, ops)
	if err := o.Open(t.Context(), formatRequest(t, "")); err != nil {
		t.Fatal(err)
	}
	if err := o.Open(t.Context(), formatRequest(t, "65532:65532")); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("got %v, want ErrNotAuthorized", err)
	}
}

func TestSystemOpsBlank(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	zeros := make([]byte, blankProbeBytes+4096)
	small := make([]byte, 8192)
	written := make([]byte, 8192)
	written[17] = 1

	var ops SystemOps
	for name, tc := range map[string]struct {
		data  []byte
		blank bool
	}{
		"zeros":       {zeros, true},
		"small zeros": {small, true},
		"written":     {written, false},
	} {
		p := write(name, tc.data)
		blank, err := ops.Blank(t.Context(), p)
		if err != nil || blank != tc.blank {
			t.Errorf("%s: Blank = %v, %v; want %v", name, blank, err, tc.blank)
		}
	}
	if _, err := ops.Blank(t.Context(), write("empty", nil)); err == nil {
		t.Error("an empty device read as blank")
	}
}

func TestMkfsArgs(t *testing.T) {
	got := mkfsArgs("/dev/mapper/x", "65532:65532")
	want := []string{"-q", "-F", "-m", "0", "-E", "nodiscard,root_owner=65532:65532", "/dev/mapper/x"}
	if !slices.Equal(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
	if got := mkfsArgs("/dev/mapper/x", ""); got[5] != "nodiscard" {
		t.Fatalf("args without owner = %v", got)
	}
}
