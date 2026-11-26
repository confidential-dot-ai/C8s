package allowlist

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// table is a text table: the column headings and one row of cells per record.
type table struct {
	Columns []string
	Rows    [][]string
}

func writeTable(w io.Writer, t table) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(t.Columns, "\t"))
	for _, row := range t.Rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
}

// change is one named thing a diff reports: added ("+"), removed ("-") or
// changed ("~"), with one line per field that changed.
type change struct {
	Marker string
	Name   string
	Fields []fieldChange
}

// fieldChange is one field's before and after.
type fieldChange struct {
	Name string
	From string
	To   string
}

// writeChanges writes changes under heading, and nothing at all when there are
// none.
func writeChanges(w io.Writer, heading string, changes []change) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintln(w, heading)
	for _, c := range changes {
		fmt.Fprintln(w, c.Marker+" "+c.Name)
		for _, f := range c.Fields {
			fmt.Fprintf(w, "    %s: %s -> %s\n", f.Name, f.From, f.To)
		}
	}
}
