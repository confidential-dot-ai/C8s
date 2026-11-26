package allowlist

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

// setRow is one component set as the CLI reports it.
type setRow struct {
	Version  string `json:"version"`
	State    string `json:"state"`
	Deadline string `json:"deadline,omitempty"`
	Entries  int    `json:"entries"`
	Digest   string `json:"digest"`
}

func setRows(sets map[string]pkgallowlist.ComponentSet, now time.Time) []setRow {
	rows := make([]setRow, 0, len(sets))
	for _, version := range slices.SortedFunc(maps.Keys(sets), pkgallowlist.CompareSetVersions) {
		set := sets[version]
		row := setRow{Version: version, State: "current", Entries: len(set.Entries), Digest: set.DigestString()}
		if !set.Current() {
			row.Deadline = set.Retire.Deadline.UTC().Format(time.RFC3339)
			row.State = "retiring"
			if !set.InForce(now) {
				row.State = "ended"
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func printSetRows(w io.Writer, rows []setRow) {
	fmt.Fprintf(w, "component sets (%d):\n", len(rows))
	if len(rows) == 0 {
		return
	}
	writeTable(w, setTable(rows))
}

func setTable(rows []setRow) table {
	t := table{Columns: []string{"VERSION", "STATE", "ENTRIES", "DIGEST"}}
	for _, row := range rows {
		t.Rows = append(t.Rows, []string{row.Version, setState(row), strconv.Itoa(row.Entries), row.Digest})
	}
	return t
}

func setState(row setRow) string {
	switch row.State {
	case "retiring":
		return "retiring until " + row.Deadline
	case "ended":
		return "ended " + row.Deadline
	default:
		return row.State
	}
}
