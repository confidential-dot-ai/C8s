package cdsha

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	haapi "github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

const forceUsage = "write a set that evicts the builds a majority of the members run"

func newAcceptImageCmd(o *options) *cobra.Command {
	var newPin, version, floor string
	var force bool
	cmd := &cobra.Command{
		Use:   "accept-image",
		Short: "Accept a new CDS build on the replica set's chain",
		Long: `Write an accepted-builds entry: the current set plus the build --new-pin
pins, at --version, without every build below --floor. Replicas of the new
build then get the keys from their peers. A set that evicts the builds a
majority of the members run is refused without --force (U2).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validFloor("--floor", floor); err != nil {
				return err
			}
			pin, err := os.ReadFile(newPin)
			if err != nil {
				return fmt.Errorf("--new-pin: %w", err)
			}
			return o.writeBuilds(cmd.Context(), cmd.OutOrStdout(), force, func(current []cdschain.Build) []cdschain.Build {
				return above(append(current, cdschain.Build{Measurements: string(pin), Version: version}), floor)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&newPin, "new-pin", "", "measurements document pinning the CDS build to accept, as 'c8s cds config new' writes it")
	f.StringVar(&version, "version", "", "release version of that build")
	f.StringVar(&floor, "floor", "", "evict every build below this version")
	f.BoolVar(&force, "force", false, forceUsage)
	_ = cmd.MarkFlagRequired("new-pin")
	_ = cmd.MarkFlagRequired("version")
	return cmd
}

func newRaiseFloorCmd(o *options) *cobra.Command {
	var to string
	var force bool
	cmd := &cobra.Command{
		Use:   "raise-floor",
		Short: "Evict every accepted CDS build below a version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !semver.IsValid(to) {
				return fmt.Errorf("--to %q is not a semantic version", to)
			}
			return o.writeBuilds(cmd.Context(), cmd.OutOrStdout(), force, func(current []cdschain.Build) []cdschain.Build { return above(current, to) })
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "the new build floor")
	cmd.Flags().BoolVar(&force, "force", false, forceUsage)
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// validFloor refuses a --floor that is not a semantic version ("" evicts
// nothing): semver.Compare orders an invalid version below every valid one,
// so it would evict nothing.
func validFloor(flag, floor string) error {
	if floor != "" && !semver.IsValid(floor) {
		return fmt.Errorf("%s %q is not a semantic version (for example v1.4.0)", flag, floor)
	}
	return nil
}

// above is the builds at or above floor ("" keeps all).
func above(builds []cdschain.Build, floor string) []cdschain.Build {
	return slices.DeleteFunc(slices.Clone(builds), func(b cdschain.Build) bool {
		return floor != "" && semver.Compare(b.Version, floor) < 0
	})
}

// writeBuilds writes the accepted set next(current). A set that a majority
// of the members' running builds are not in is refused without force (U2):
// the set then serves nothing until replacements join. A write another
// writer beat (409) is re-read and retried until --retry-for has passed.
func (o *options) writeBuilds(ctx context.Context, out io.Writer, force bool, next func([]cdschain.Build) []cdschain.Build) error {
	w, err := o.writer(ctx)
	if err != nil {
		return err
	}
	var statuses []*haapi.Status
	deadline := time.Now().Add(o.retryFor)
	for attempt := 1; ; attempt++ {
		state, err := w.verified(ctx)
		if err != nil {
			return err
		}
		builds := next(state.Accepted)
		if !force {
			if statuses == nil {
				urls := make([]string, len(state.Endpoints))
				for i, e := range state.Endpoints {
					urls[i] = cmdsutil.CDSURL(e)
				}
				statuses = o.statuses(ctx, urls)
			}
			if running := runningIn(statuses, builds); running < len(statuses)/2+1 {
				return fmt.Errorf("only %d of %d members run a build of the new set: the set would serve nothing until replacements join; pass --force to write it anyway", running, len(statuses))
			}
		}
		head, err := w.append(ctx, state, cdschain.TypeAccepted, cdschain.Accepted{Accepted: builds})
		if errors.Is(err, errHeadMoved) && time.Now().Before(deadline) {
			// Jittered, so two commands racing each other drift apart.
			time.Sleep(min(time.Duration(attempt)*100*time.Millisecond, time.Second) + rand.N(100*time.Millisecond))
			continue
		}
		if err != nil {
			return fmt.Errorf("after %d attempts: %w", attempt, err)
		}
		fmt.Fprintf(out, "accepted %d builds at head %d (%s)\n", len(builds), head.Seq, head.Hash)
		return nil
	}
}

// runningIn counts the members whose own build is in builds.
func runningIn(statuses []*haapi.Status, builds []cdschain.Build) int {
	n := 0
	for _, s := range statuses {
		if s != nil && s.IsMember && slices.ContainsFunc(builds, func(b cdschain.Build) bool { return b.Version == s.Build }) {
			n++
		}
	}
	return n
}
