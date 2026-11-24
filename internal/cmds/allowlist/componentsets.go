package allowlist

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlistclient"
)

// setChange is one command's change to the components section, made again
// onto a newer allowlist when another write lands first.
type setChange struct {
	// require are the versions the document first read must hold, so a
	// mistyped version stops the command before it writes anything.
	require []string
	// refuse reports why the change cannot be made to the document it would
	// be written onto. It runs on the document first read and on every newer
	// one a racing write leaves, where the change may no longer apply.
	refuse  func(live map[string]pkgallowlist.ComponentSet) error
	rebuild func(sets map[string]pkgallowlist.ComponentSet)
	force   bool
}

// addChange puts set in under version, retires the sets named in deadlines and
// drops the sets named in remove.
func addChange(version string, set pkgallowlist.ComponentSet, deadlines map[string]pkgallowlist.Deadline, remove []string) setChange {
	retired := slices.Collect(maps.Keys(deadlines))
	return setChange{
		require: slices.Concat(retired, remove),
		refuse: func(live map[string]pkgallowlist.ComponentSet) error {
			// The same entries under that version are the set being added,
			// by a write of this command that landed unconfirmed.
			if held, ok := live[version]; ok && held.DigestString() != set.DigestString() {
				return fmt.Errorf("the allowlist already holds component set %s; retire or remove it, or publish the components under a new version", version)
			}
			return requireSets(live, retired)
		},
		rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
			sets[version] = set
			for v, deadline := range deadlines {
				retireSet(sets, v, &pkgallowlist.Retirement{Deadline: deadline})
			}
			for _, v := range remove {
				delete(sets, v)
			}
		},
	}
}

func retireChange(version string, deadline pkgallowlist.Deadline, force bool) setChange {
	return setChange{
		require: []string{version},
		refuse:  func(live map[string]pkgallowlist.ComponentSet) error { return requireSets(live, []string{version}) },
		rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
			retireSet(sets, version, &pkgallowlist.Retirement{Deadline: deadline})
		},
		force: force,
	}
}

func unretireChange(version string) setChange {
	return setChange{
		require: []string{version},
		refuse:  func(live map[string]pkgallowlist.ComponentSet) error { return requireSets(live, []string{version}) },
		rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
			retireSet(sets, version, nil)
		},
	}
}

func removeChange(version string, force bool) setChange {
	return setChange{
		require: []string{version},
		refuse:  nothingToConflictWith,
		rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
			delete(sets, version)
		},
		force: force,
	}
}

// nothingToConflictWith is the refusal of a change no other write can take
// away: another write dropping the set it drops leaves the result it asks for.
func nothingToConflictWith(map[string]pkgallowlist.ComponentSet) error { return nil }

// applySetChange reads the live allowlist, writes the change onto it, and
// prints the sets the write left.
func applySetChange(cmd *cobra.Command, o *options, change setChange) error {
	c, err := o.client(ctx(cmd))
	if err != nil {
		return err
	}
	read, err := readForWrite(ctx(cmd), c)
	if err != nil {
		return err
	}
	if err := requireSets(read.document.Components, change.require); err != nil {
		return err
	}
	signer, err := o.signer()
	if err != nil {
		return err
	}
	sets, err := writeSets(cmd, c, read, change, signer)
	if err != nil {
		return err
	}
	printSetRows(cmd.OutOrStdout(), setRows(sets, time.Now()))
	return nil
}

// result is the components section the change builds from live.
func (change setChange) result(live map[string]pkgallowlist.ComponentSet) (map[string]pkgallowlist.ComponentSet, error) {
	sets := maps.Clone(live)
	if sets == nil {
		sets = map[string]pkgallowlist.ComponentSet{}
	}
	change.rebuild(sets)
	if change.force {
		return sets, nil
	}
	return sets, requireCurrentSet(sets)
}

// writeSets writes read's document with the change made to its components
// section, conditional on the version it was read at, and returns the sets it
// wrote. A document that already holds the result is left alone.
//
// When another write landed since, the change is made again onto the newer
// document, which is refused the same way the document first read was: the
// racing write may have taken the sets this change names away, or published
// the version it adds.
func writeSets(cmd *cobra.Command, c allowlistclient.Client, read allowlistRead,
	change setChange, signer allowlistclient.Authorizer) (map[string]pkgallowlist.ComponentSet, error) {
	for attempt := 1; ; attempt++ {
		if err := change.refuse(read.document.Components); err != nil {
			return nil, err
		}
		sets, err := change.result(read.document.Components)
		if err != nil {
			return nil, err
		}
		doc := documentWithSets(read, sets)
		made, err := sameDocument(&doc, read.document)
		if err != nil {
			return nil, err
		}
		if made {
			return sets, nil
		}
		newer, err := conditionalWrite(cmd, c, &doc, read, attempt, signer)
		if err != nil {
			return nil, writeFailure("change the component sets in one write", "no set changed", err)
		}
		if newer == nil {
			return sets, nil
		}
		reportRacingWrite(cmd, read, *newer)
		read = *newer
	}
}

func documentWithSets(read allowlistRead, sets map[string]pkgallowlist.ComponentSet) pkgallowlist.Allowlist {
	return pkgallowlist.Allowlist{
		Schema:     read.document.Schema,
		Workloads:  read.document.Workloads,
		Components: sets,
	}
}

func retireSet(sets map[string]pkgallowlist.ComponentSet, version string, retire *pkgallowlist.Retirement) {
	set, ok := sets[version]
	if !ok {
		return
	}
	set.Retire = retire
	sets[version] = set
}

// requireSets refuses a change to a set the allowlist does not hold.
func requireSets(live map[string]pkgallowlist.ComponentSet, versions []string) error {
	for _, version := range versions {
		if _, ok := live[version]; !ok {
			return fmt.Errorf("the allowlist holds no component set %s", version)
		}
	}
	return nil
}

// requireCurrentSet refuses a result no new pod can join: every set it holds
// is retiring, or it holds none at all.
func requireCurrentSet(sets map[string]pkgallowlist.ComponentSet) error {
	for _, set := range sets {
		if set.Current() {
			return nil
		}
	}
	return errors.New("the result leaves no current component set, so no new pod would get its c8s components; re-run with --force if that is intended")
}
